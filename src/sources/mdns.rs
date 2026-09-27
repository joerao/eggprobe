//! mDNS / DNS-SD. Enumerates every advertised service type with the meta-query,
//! then browses the known types nobody announced, because some responders
//! ignore the meta-query. Staging it keeps multicast traffic down: on some
//! Wi-Fi networks a burst of mDNS stalls unicast traffic for everyone.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::time::Duration;

use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent};
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::{Cancel, Sink, cancelled, device_info};
use crate::inventory::{FindingKind, MdnsService, NameSource, SourceState};

const META_QUERY: &str = "_services._dns-sd._udp.local.";

/// Most responders answer the meta-query within a second.
const KNOWN_TYPES_AFTER: Duration = Duration::from_millis(1500);

/// Types browsed even when nobody answers the meta-query.
pub const KNOWN_TYPES: &[&str] = &[
    "_http._tcp.local.",
    "_https._tcp.local.",
    "_ssh._tcp.local.",
    "_sftp-ssh._tcp.local.",
    "_smb._tcp.local.",
    "_afpovertcp._tcp.local.",
    "_nfs._tcp.local.",
    "_ftp._tcp.local.",
    "_ipp._tcp.local.",
    "_ipps._tcp.local.",
    "_printer._tcp.local.",
    "_pdl-datastream._tcp.local.",
    "_scanner._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",
    "_googlecast._tcp.local.",
    "_spotify-connect._tcp.local.",
    "_sonos._tcp.local.",
    "_hap._tcp.local.",
    "_homekit._tcp.local.",
    "_hue._tcp.local.",
    "_wled._tcp.local.",
    "_mqtt._tcp.local.",
    "_coap._udp.local.",
    "_daap._tcp.local.",
    "_dacp._tcp.local.",
    "_touch-able._tcp.local.",
    "_companion-link._tcp.local.",
    "_sleep-proxy._udp.local.",
    "_device-info._tcp.local.",
    "_rtsp._tcp.local.",
    "_nvstream._tcp.local.",
    "_workstation._tcp.local.",
    "_net-assistant._udp.local.",
    "_rdlink._tcp.local.",
    "_esphomelib._tcp.local.",
    "_home-assistant._tcp.local.",
    "_matter._tcp.local.",
    "_matterc._udp.local.",
    "_meshcop._udp.local.",
    "_amzn-wplay._tcp.local.",
    "_roku-rcp._tcp.local.",
    "_appletv-v2._tcp.local.",
    "_homebridge._tcp.local.",
    "_shelly._tcp.local.",
    "_hubitat._tcp.local.",
    "_node-red._tcp.local.",
    "_octoprint._tcp.local.",
    "_adguard._tcp.local.",
    "_unifi._tcp.local.",
    "_plex._tcp.local.",
    "_plexmediasvr._tcp.local.",
    "_jellyfin._tcp.local.",
    "_emby._tcp.local.",
];

pub async fn run(sink: Sink, interface: Option<String>, listen: Duration, cancel: &mut Cancel) {
    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            sink.status(SourceState::Unavailable(format!(
                "cannot open mDNS socket: {e}"
            )));
            return;
        }
    };
    if let Some(name) = &interface {
        let _ = daemon.disable_interface(IfKind::All);
        let _ = daemon.enable_interface(IfKind::Name(name.clone()));
    }
    let _ = daemon.disable_interface(IfKind::IPv6);

    let (tx, mut rx) = mpsc::unbounded_channel::<ServiceEvent>();
    let mut browsing = BTreeSet::new();
    let browse = |ty: &str, browsing: &mut BTreeSet<String>| -> Result<(), String> {
        if !browsing.insert(ty.to_string()) {
            return Ok(());
        }
        let receiver = daemon.browse(ty).map_err(|e| e.to_string())?;
        let tx = tx.clone();
        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                if tx.send(event).is_err() {
                    break;
                }
            }
        });
        Ok(())
    };
    if let Err(e) = browse(META_QUERY, &mut browsing) {
        let _ = daemon.shutdown();
        sink.status(SourceState::Failed(format!("could not browse: {e}")));
        return;
    }

    let started = Instant::now();
    let deadline = started + listen;
    let fallback = started + KNOWN_TYPES_AFTER;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    let mut stopped = false;
    let mut fallback_done = false;
    let mut instances = 0usize;
    let mut hosts = BTreeSet::new();
    let mut announced = BTreeSet::new();
    sink.status(SourceState::Running(format!(
        "listening for {}s",
        listen.as_secs()
    )));
    loop {
        let event = tokio::select! {
            e = rx.recv() => e,
            _ = tokio::time::sleep_until(fallback), if !fallback_done => {
                fallback_done = true;
                for ty in KNOWN_TYPES {
                    let _ = browse(ty, &mut browsing);
                }
                continue;
            }
            _ = tick.tick() => {
                let ms = |d: Duration| d.as_millis() as usize;
                sink.progress(ms(started.elapsed()).min(ms(listen)), ms(listen));
                continue;
            }
            _ = cancelled(cancel) => {
                stopped = true;
                None
            }
            _ = tokio::time::sleep_until(deadline) => None,
        };
        let Some(event) = event else { break };
        match event {
            // Meta-query answers name a service type in the fullname slot.
            ServiceEvent::ServiceFound(ty, fullname) if ty == META_QUERY => {
                let ty = normalize_type(&fullname);
                announced.insert(ty.clone());
                let _ = browse(&ty, &mut browsing);
            }
            ServiceEvent::ServiceResolved(info) => {
                let host = info.host.trim_end_matches('.').to_string();
                let instance = instance_name(&info.fullname, &info.ty_domain);
                let txt: BTreeMap<String, String> = info
                    .txt_properties
                    .iter()
                    .map(|p| (p.key().to_string(), p.val_str().to_string()))
                    .collect();
                for addr in &info.addresses {
                    let IpAddr::V4(ip) = addr.to_ip_addr() else {
                        continue;
                    };
                    instances += 1;
                    hosts.insert(ip);
                    if !host.is_empty() {
                        let short = host.strip_suffix(".local").unwrap_or(&host).to_string();
                        sink.found(ip, FindingKind::Name(NameSource::Mdns, short));
                    }
                    let svc = MdnsService {
                        service_type: info.ty_domain.clone(),
                        instance: instance.clone(),
                        host: host.clone(),
                        port: info.port,
                        txt: txt.clone(),
                    };
                    if let Some(described) = device_info::from_txt(&svc) {
                        sink.found(ip, FindingKind::Info(described));
                    }
                    sink.found(ip, FindingKind::Mdns(svc));
                }
            }
            _ => {}
        }
    }
    if let Ok(done) = daemon.shutdown() {
        let _ = tokio::time::timeout(Duration::from_secs(1), done.recv_async()).await;
    }
    if stopped {
        sink.status(SourceState::Stopped);
        return;
    }
    sink.status(SourceState::Done(format!(
        "{instances} service instances on {} hosts; {} types advertised, {} browsed",
        hosts.len(),
        announced.len(),
        browsing.len() - 1
    )));
}

/// Meta-query answers arrive as `_http._tcp.local` with or without the root dot.
fn normalize_type(fullname: &str) -> String {
    let t = fullname.trim_end_matches('.');
    format!("{t}.")
}

/// `Living Room._airplay._tcp.local.` → `Living Room`.
fn instance_name(fullname: &str, ty_domain: &str) -> String {
    fullname
        .strip_suffix(ty_domain)
        .map(|s| s.trim_end_matches('.'))
        .unwrap_or(fullname)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(normalize_type("_hap._tcp.local"), "_hap._tcp.local.");
        assert_eq!(normalize_type("_hap._tcp.local."), "_hap._tcp.local.");
        assert_eq!(
            instance_name("Living Room._airplay._tcp.local.", "_airplay._tcp.local."),
            "Living Room"
        );
        assert_eq!(instance_name("odd", "_x._tcp.local."), "odd");
    }
}
