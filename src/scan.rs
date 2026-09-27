//! Runs the sources in turn, feeding one coordinator as findings arrive.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc;

use crate::inventory::{Event, Inventory, SourceState};
use crate::netif::Target;
use crate::sources::{
    Cancel, Sink, cancelled, device_info, mdns, names, neighbors, tailscale, tcp, tuya,
};

pub const SOURCES: &[&str] = &[
    "tailscale",
    "tuya",
    "neighbors",
    "tcp-sweep",
    "names",
    "port-probe",
    "tailnet-probe",
    "mdns",
    "device-info",
];

/// Linux defaults: 3 ARP solicitations, 1 s apart.
const ARP_SETTLE: Duration = Duration::from_secs(2);

/// TCP stalls on some Wi-Fi networks for a few seconds after mDNS browsing
/// (see docs/design.md), so asking devices over HTTP waits this long.
const MDNS_SETTLE: Duration = Duration::from_secs(3);

#[derive(Clone)]
pub struct Options {
    pub mdns_listen: Duration,
    pub skip: Vec<String>,
}

pub type Shared = Arc<Mutex<Inventory>>;

/// Runs one scan to completion. Findings land in `inv` as they arrive, so a
/// caller that stops waiting still has everything found so far.
pub async fn run(target: &Target, opts: &Options, inv: Shared, mut cancel: Cancel) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let skipped = |name: &str| opts.skip.iter().any(|s| s == name);
    let stop = |cancel: &Cancel| *cancel.borrow();
    for &name in SOURCES {
        let state = if skipped(name) {
            SourceState::Skipped
        } else {
            SourceState::Pending
        };
        let _ = tx.send(Event::Status(name, state));
    }

    let coordinator = {
        let inv = inv.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                inv.lock().unwrap().apply(event, SystemTime::now());
            }
        })
    };

    let iface = target.interface.clone();
    let hosts: Vec<Ipv4Addr> = target.subnet.hosts().collect();

    // Tuya devices broadcast on their own; listening sends nothing, so it
    // runs alongside everything else for the whole scan.
    let tuya_listener = (!skipped("tuya")).then(|| {
        let (stop, until) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(tuya::run(
            Sink::new(tx.clone(), "tuya"),
            cancel.clone(),
            until,
        ));
        (stop, task)
    });

    // One source at a time on the wire. On some Wi-Fi networks, TCP connects
    // during mDNS browsing, and for a while after it, mostly time out — for
    // every process on the machine, not just ours.
    // So TCP goes first and mDNS last. Order: cached neighbors (instant),
    // sweep, the neighbor table it filled, ports on whoever turned up, mDNS.
    // Tailscale is a local query with no network traffic, so it goes first.
    if !skipped("tailscale") {
        let peers = tailscale::run(&Sink::new(tx.clone(), "tailscale")).await;
        let _ = tx.send(Event::Tailnet(peers));
    }
    let neigh = Sink::new(tx.clone(), "neighbors");
    if !skipped("neighbors") {
        neighbors::read(&neigh, iface.as_deref(), "initial").await;
    }
    if !skipped("tcp-sweep") && !stop(&cancel) {
        let sweep = Sink::new(tx.clone(), "tcp-sweep");
        tcp::probe(
            &sweep,
            &hosts,
            tcp::DISCOVERY_PORTS,
            &tcp::SWEEP,
            "sweep",
            &mut cancel,
        )
        .await;
        // The kernel keeps retrying ARP for empty addresses for a few seconds
        // after the sweep; probing ports during that storm loses answers.
        // Late ARP replies land meanwhile.
        tokio::select! {
            _ = tokio::time::sleep(ARP_SETTLE) => {}
            _ = cancelled(&mut cancel) => {}
        }
        if !skipped("neighbors") && !stop(&cancel) {
            neighbors::read(&neigh, iface.as_deref(), "post-sweep").await;
        }
    }
    if !skipped("names") && !stop(&cancel) {
        // Every host found so far, responding or not: a stale ARP entry may
        // still belong to a machine that answers NetBIOS.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let known: Vec<Ipv4Addr> = inv.lock().unwrap().devices.keys().copied().collect();
        let sink = Sink::new(tx.clone(), "names");
        names::run(&sink, &known, &target.dns, &mut cancel).await;
    }
    if !skipped("port-probe") && !stop(&cancel) {
        // Let the coordinator drain what earlier sources sent.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let alive: Vec<Ipv4Addr> = inv
            .lock()
            .unwrap()
            .devices
            .values()
            .filter(|d| d.responding)
            .map(|d| d.ip)
            .collect();
        let ports = Sink::new(tx.clone(), "port-probe");
        tcp::probe(
            &ports,
            &alive,
            tcp::SIGNATURE_PORTS,
            &tcp::PORTS,
            "signature ports",
            &mut cancel,
        )
        .await;
    }
    if !skipped("tailnet-probe") && !stop(&cancel) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let peers = {
            let inv = inv.lock().unwrap();
            crate::inventory::probe_peers(&inv.tailnet, &inv.devices)
        };
        let sink = Sink::new(tx.clone(), "tailnet-probe");
        if peers.is_empty() {
            sink.status(SourceState::Done("no online peers off this LAN".into()));
        } else {
            tcp::probe(
                &sink,
                &peers,
                tcp::SIGNATURE_PORTS,
                &tcp::TAILNET,
                "tailnet peers",
                &mut cancel,
            )
            .await;
        }
    }
    let mut mdns_ran = false;
    if !skipped("mdns") && !stop(&cancel) {
        mdns::run(
            Sink::new(tx.clone(), "mdns"),
            iface.clone(),
            opts.mdns_listen,
            &mut cancel,
        )
        .await;
        mdns_ran = true;
    }
    if !skipped("device-info") && !stop(&cancel) {
        let sink = Sink::new(tx.clone(), "device-info");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let targets = {
            let inv = inv.lock().unwrap();
            device_info::targets(inv.devices.values().chain(inv.remote.values()))
        };
        if mdns_ran && !targets.is_empty() {
            sink.status(SourceState::Running("waiting for mDNS to settle".into()));
            tokio::select! {
                _ = tokio::time::sleep(MDNS_SETTLE) => {}
                _ = cancelled(&mut cancel) => {}
            }
        }
        if !stop(&cancel) {
            device_info::run(&sink, targets, target.subnet, &mut cancel).await;
        }
    }

    if let Some((stop, task)) = tuya_listener {
        let _ = stop.send(());
        let _ = task.await;
    }

    // The coordinator stops once every sender is gone.
    drop(neigh);
    drop(tx);
    let _ = coordinator.await;
    if stop(&cancel) {
        // Stages that never started read as stopped, not pending.
        inv.lock().unwrap().stop_running();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn returns_when_every_source_is_skipped() {
        let target = Target {
            interface: None,
            address: None,
            gateway: None,
            dns: vec![],
            subnet: "127.0.0.1/32".parse().unwrap(),
        };
        let opts = Options {
            mdns_listen: Duration::from_secs(1),
            skip: SOURCES.iter().map(|s| s.to_string()).collect(),
        };
        let inv = Arc::new(Mutex::new(Inventory::new(target.subnet, None, None)));
        let (_keep, cancel) = tokio::sync::watch::channel(false);
        tokio::time::timeout(
            Duration::from_secs(5),
            run(&target, &opts, inv.clone(), cancel),
        )
        .await
        .expect("scan must finish once its sources have");
        let inv = inv.lock().unwrap();
        assert!(inv.sources.iter().all(|(_, s)| *s == SourceState::Skipped));
    }
}
