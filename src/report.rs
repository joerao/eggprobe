//! The `--scan` JSON report.

use std::time::SystemTime;

use serde::Serialize;

use std::net::Ipv4Addr;

use crate::classify::{self, Classification};
use crate::inventory::{
    Device, DeviceInfo, Evidence, Inventory, Peer, SourceState, link_tailnet, rfc3339,
};
use crate::netif::Target;
use std::collections::BTreeSet;

#[derive(Serialize)]
pub struct Report<'a> {
    pub eggprobe: &'static str,
    pub target: &'a Target,
    #[serde(serialize_with = "rfc3339")]
    pub started: SystemTime,
    pub elapsed_ms: u128,
    /// False when cancelled or when any source failed.
    pub complete: bool,
    pub cancelled: bool,
    pub sources: Vec<SourceReport>,
    pub stats: Stats,
    pub devices: Vec<DeviceReport>,
    pub tailnet: Vec<PeerReport>,
}

#[derive(Serialize)]
pub struct DeviceReport {
    #[serde(flatten)]
    pub device: Device,
    pub classification: Classification,
    /// The device's MagicDNS name, when it is also on the tailnet.
    pub tailnet: Option<String>,
}

#[derive(Serialize)]
pub struct PeerReport {
    #[serde(flatten)]
    pub peer: Peer,
    /// The same machine's LAN address, when it could be matched.
    pub lan_address: Option<Ipv4Addr>,
    /// What probing its Tailscale address found, for peers not on the LAN.
    pub probed: Option<Probed>,
    pub classification: Classification,
}

#[derive(Serialize)]
pub struct Probed {
    pub open_ports: BTreeSet<u16>,
    pub info: Vec<DeviceInfo>,
    pub evidence: BTreeSet<Evidence>,
}

#[derive(Serialize)]
pub struct SourceReport {
    pub name: &'static str,
    #[serde(flatten)]
    pub state: SourceState,
}

#[derive(Serialize)]
pub struct Stats {
    pub devices: usize,
    pub responding: usize,
    pub ignored_outside_subnet: usize,
    pub tailnet_peers: usize,
}

pub fn build<'a>(
    target: &'a Target,
    inv: &Inventory,
    started: SystemTime,
    cancelled: bool,
) -> Report<'a> {
    let links = link_tailnet(&inv.tailnet, &inv.devices);
    let peer_of = |ip: Ipv4Addr| inv.tailnet.iter().find(|p| links.get(&p.id) == Some(&ip));
    let devices: Vec<DeviceReport> = inv
        .devices
        .values()
        .map(|d| {
            let peer = peer_of(d.ip);
            DeviceReport {
                classification: classify::classify(d, peer),
                tailnet: peer.map(|p| p.dns_name.clone()),
                device: d.clone(),
            }
        })
        .collect();
    let tailnet: Vec<PeerReport> = inv
        .tailnet
        .iter()
        .map(|p| {
            let lan = links.get(&p.id).copied();
            let remote = p.ipv4().and_then(|ip| inv.remote.get(&ip));
            PeerReport {
                classification: match lan.and_then(|ip| inv.devices.get(&ip)).or(remote) {
                    Some(d) => classify::classify(d, Some(p)),
                    None => classify::classify_peer(p),
                },
                lan_address: lan,
                probed: remote.map(|d| Probed {
                    open_ports: d.open_ports.clone(),
                    info: d.info.clone(),
                    evidence: d.evidence.clone(),
                }),
                peer: p.clone(),
            }
        })
        .collect();
    Report {
        eggprobe: env!("CARGO_PKG_VERSION"),
        target,
        started,
        elapsed_ms: started.elapsed().map(|d| d.as_millis()).unwrap_or(0),
        complete: !cancelled && !inv.any_failed(),
        cancelled,
        sources: inv
            .sources
            .iter()
            .map(|(name, state)| SourceReport {
                name,
                state: state.clone(),
            })
            .collect(),
        stats: Stats {
            devices: devices.len(),
            responding: devices.iter().filter(|d| d.device.responding).count(),
            ignored_outside_subnet: inv.ignored_outside_subnet,
            tailnet_peers: tailnet.iter().filter(|p| !p.peer.is_self).count(),
        },
        devices,
        tailnet,
    }
}
