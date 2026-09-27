//! The device table. Sources send `Event`s to one coordinator, which is the only
//! writer; readers take brief snapshot copies.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::SystemTime;

use ipnet::Ipv4Net;
use serde::{Serialize, Serializer};

pub use crate::sources::tailscale::Peer;

/// A source's name, as shown in the report and (later) the footer.
pub type SourceName = &'static str;

#[derive(Debug, Clone)]
pub enum Event {
    Found(Finding),
    Status(SourceName, SourceState),
    /// Work done out of work planned, for progress bars.
    Progress(SourceName, usize, usize),
    /// The whole tailnet, replacing any earlier list.
    Tailnet(Vec<Peer>),
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub ip: Ipv4Addr,
    pub source: SourceName,
    pub kind: FindingKind,
}

#[derive(Debug, Clone)]
pub enum FindingKind {
    /// The host answered: a TCP accept or refusal, a reachable neighbor entry,
    /// or an mDNS announcement.
    Responded(String),
    /// A neighbor-table entry exists but the kernel no longer vouches for it.
    Cached,
    Mac(String),
    OpenPort(u16),
    Name(NameSource, String),
    /// The NetBIOS workgroup or domain a Windows or Samba host belongs to.
    Workgroup(String),
    Mdns(MdnsService),
    /// What the device says about itself, from its own API or TXT records.
    Info(DeviceInfo),
}

/// Where a name came from. Declared in display preference: what the device
/// told the router's DHCP server reads best; its own mDNS claim can carry a
/// conflict suffix like `-(2)`; NetBIOS names are upper case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NameSource {
    Dns,
    Mdns,
    Netbios,
}

impl NameSource {
    pub fn label(self) -> &'static str {
        match self {
            NameSource::Dns => "reverse DNS",
            NameSource::Mdns => "mDNS",
            NameSource::Netbios => "NetBIOS",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "lowercase")]
pub enum SourceState {
    Pending,
    Running(String),
    Done(String),
    /// The source cannot run here (missing tool, permission); not an error.
    Unavailable(String),
    Failed(String),
    Skipped,
    /// Cancelled before it finished; its findings so far are kept.
    Stopped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MdnsService {
    pub service_type: String,
    pub instance: String,
    pub host: String,
    pub port: u16,
    pub txt: BTreeMap<String, String>,
}

/// A device's own description of itself: from its HTTP API (WLED's
/// `/json/info`) or from the TXT records of a service that carries one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceInfo {
    /// Which description this is: `wled`, `esphome`, `home-assistant`…
    pub protocol: &'static str,
    /// Where it came from: a URL, or the mDNS service type.
    pub from: String,
    /// The name its owner gave it, when that is not a factory default.
    pub name: Option<String>,
    pub product: Option<String>,
    pub model: Option<String>,
    pub firmware: Option<String>,
    pub mac: Option<String>,
    /// Everything else worth showing, in display order.
    pub details: Vec<Detail>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Detail {
    pub label: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub ip: Ipv4Addr,
    pub mac: Option<String>,
    /// The best of `names`, shortened to its first label.
    pub hostname: Option<String>,
    /// Every name the device answered to, by how it was learned. DNS names
    /// are kept in full, including the router's search domain.
    pub names: BTreeMap<NameSource, String>,
    pub workgroup: Option<String>,
    /// True once any source saw the host answer during this run. False means
    /// it is only known from a stale neighbor-table entry.
    pub responding: bool,
    pub is_self: bool,
    pub is_gateway: bool,
    pub open_ports: BTreeSet<u16>,
    pub mdns_services: Vec<MdnsService>,
    /// What the device says about itself, one entry per protocol.
    pub info: Vec<DeviceInfo>,
    /// Every source that contributed, with what it saw. The classifier will
    /// cite these as its reasons.
    pub evidence: BTreeSet<Evidence>,
    #[serde(serialize_with = "rfc3339")]
    pub first_seen: SystemTime,
    #[serde(serialize_with = "rfc3339")]
    pub last_seen: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Evidence {
    pub source: SourceName,
    pub detail: String,
}

impl Device {
    fn new(ip: Ipv4Addr, now: SystemTime) -> Self {
        Device {
            ip,
            mac: None,
            hostname: None,
            names: BTreeMap::new(),
            workgroup: None,
            responding: false,
            is_self: false,
            is_gateway: false,
            open_ports: BTreeSet::new(),
            mdns_services: Vec::new(),
            info: Vec::new(),
            evidence: BTreeSet::new(),
            first_seen: now,
            last_seen: now,
        }
    }
}

pub struct Inventory {
    pub subnet: Ipv4Net,
    pub self_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub devices: BTreeMap<Ipv4Addr, Device>,
    pub sources: Vec<(SourceName, SourceState)>,
    pub progress: BTreeMap<SourceName, (usize, usize)>,
    /// Tailscale peers. They live outside the subnet, so they are kept
    /// apart from `devices` and linked to them by name when shown.
    pub tailnet: Vec<Peer>,
    /// What probing tailnet peers at their Tailscale addresses found, keyed
    /// by that address.
    pub remote: BTreeMap<Ipv4Addr, Device>,
    /// Findings for addresses outside the subnet (other interfaces, VPNs,
    /// container bridges) are counted rather than silently mixed in.
    pub ignored_outside_subnet: usize,
}

impl Inventory {
    pub fn new(subnet: Ipv4Net, self_ip: Option<Ipv4Addr>, gateway: Option<Ipv4Addr>) -> Self {
        Inventory {
            subnet,
            self_ip,
            gateway,
            devices: BTreeMap::new(),
            sources: Vec::new(),
            progress: BTreeMap::new(),
            tailnet: Vec::new(),
            remote: BTreeMap::new(),
            ignored_outside_subnet: 0,
        }
    }

    pub fn apply(&mut self, event: Event, now: SystemTime) {
        match event {
            Event::Status(name, state) => match self.sources.iter_mut().find(|(n, _)| *n == name) {
                Some(entry) => entry.1 = state,
                None => self.sources.push((name, state)),
            },
            Event::Found(f) => self.apply_finding(f, now),
            Event::Tailnet(peers) => self.tailnet = peers,
            Event::Progress(name, done, total) => {
                self.progress.insert(name, (done, total));
            }
        }
    }

    fn apply_finding(&mut self, f: Finding, now: SystemTime) {
        let dev = if self.subnet.contains(&f.ip) {
            let (self_ip, gateway) = (self.self_ip, self.gateway);
            self.devices.entry(f.ip).or_insert_with(|| {
                let mut d = Device::new(f.ip, now);
                d.is_self = self_ip == Some(f.ip);
                d.is_gateway = gateway == Some(f.ip);
                d
            })
        } else if let Some(peer) = self.tailnet.iter().find(|p| p.ipv4() == Some(f.ip)) {
            self.remote.entry(f.ip).or_insert_with(|| {
                let mut d = Device::new(f.ip, now);
                // Its MagicDNS name: for links, and for classification.
                if !peer.dns_name.is_empty() {
                    d.names.insert(NameSource::Dns, peer.dns_name.clone());
                    d.hostname = Some(short_name(&peer.dns_name));
                }
                d
            })
        } else {
            self.ignored_outside_subnet += 1;
            return;
        };
        dev.last_seen = now;
        let detail = match f.kind {
            FindingKind::Responded(how) => {
                dev.responding = true;
                how
            }
            FindingKind::Cached => "in neighbor table (stale)".to_string(),
            FindingKind::Mac(mac) => {
                let detail = format!("MAC {mac}");
                dev.mac = Some(mac);
                detail
            }
            FindingKind::OpenPort(port) => {
                dev.open_ports.insert(port);
                format!("TCP {port} open")
            }
            FindingKind::Name(via, name) => {
                let detail = format!("name {name} ({})", via.label());
                dev.names.insert(via, name);
                dev.hostname = dev.names.values().next().map(|n| short_name(n));
                detail
            }
            FindingKind::Workgroup(group) => {
                let detail = format!("NetBIOS workgroup {group}");
                dev.workgroup = Some(group);
                detail
            }
            FindingKind::Mdns(svc) => {
                dev.responding = true;
                let detail = format!("{} \"{}\"", svc.service_type, svc.instance);
                match dev
                    .mdns_services
                    .iter_mut()
                    .find(|s| s.service_type == svc.service_type && s.instance == svc.instance)
                {
                    Some(existing) => *existing = svc,
                    None => dev.mdns_services.push(svc),
                }
                detail
            }
            FindingKind::Info(info) => {
                let mut detail = format!("{} reports", info.protocol);
                for part in [&info.name, &info.product, &info.firmware]
                    .into_iter()
                    .flatten()
                {
                    detail.push_str(&format!(" “{part}”"));
                }
                match dev.info.iter_mut().find(|i| i.protocol == info.protocol) {
                    Some(existing) => *existing = info,
                    None => dev.info.push(info),
                }
                detail
            }
        };
        dev.evidence.insert(Evidence {
            source: f.source,
            detail,
        });
    }

    pub fn stop_running(&mut self) {
        for (_, state) in &mut self.sources {
            if matches!(state, SourceState::Pending | SourceState::Running(_)) {
                *state = SourceState::Stopped;
            }
        }
    }

    pub fn any_failed(&self) -> bool {
        self.sources
            .iter()
            .any(|(_, s)| matches!(s, SourceState::Failed(_)))
    }
}

pub fn rfc3339_opt<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
    match t {
        Some(t) => rfc3339(t, s),
        None => s.serialize_none(),
    }
}

/// Online tailnet peers worth probing at their Tailscale address: not this
/// machine, not shared in from someone else's tailnet, and not already a
/// LAN device (those are probed at their LAN address).
pub fn probe_peers(peers: &[Peer], devices: &BTreeMap<Ipv4Addr, Device>) -> Vec<Ipv4Addr> {
    let links = link_tailnet(peers, devices);
    peers
        .iter()
        .filter(|p| p.online && !p.is_self && !p.shared_in && !links.contains_key(&p.id))
        .filter_map(Peer::ipv4)
        .collect()
}

/// Which LAN device each tailnet peer is, where that can be told: this
/// machine is itself on both, and otherwise a peer's hostname must match
/// exactly one device's hostname. Keyed by peer ID.
pub fn link_tailnet(
    peers: &[Peer],
    devices: &BTreeMap<Ipv4Addr, Device>,
) -> BTreeMap<String, Ipv4Addr> {
    let mut links = BTreeMap::new();
    for peer in peers {
        let found = if peer.is_self {
            devices.values().find(|d| d.is_self).map(|d| d.ip)
        } else {
            let names = [plain_name(&peer.hostname), plain_name(peer.short_name())];
            let mut matches = devices
                .values()
                .filter(|d| d.names.values().any(|h| names.contains(&plain_name(h))));
            match (matches.next(), matches.next()) {
                (Some(d), None) => Some(d.ip),
                _ => None,
            }
        };
        if let Some(ip) = found {
            links.insert(peer.id.clone(), ip);
        }
    }
    links
}

/// `tower.home.example.net` → `tower`: the part people call a machine.
pub fn short_name(name: &str) -> String {
    name.split('.').next().unwrap_or(name).to_string()
}

/// `Atlas-(2).local` → `atlas`: lowercase, first label, without the
/// counter mDNS appends when two hosts claim one name.
fn plain_name(name: &str) -> String {
    let first = name.split('.').next().unwrap_or("").to_lowercase();
    let trimmed = match first.rfind("-(") {
        Some(i) if first.ends_with(')') => &first[..i],
        _ => first.as_str(),
    };
    trimmed.trim().to_string()
}

pub fn rfc3339<S: Serializer>(t: &SystemTime, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&humantime::format_rfc3339_seconds(*t).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv() -> Inventory {
        Inventory::new(
            "10.0.0.0/24".parse().unwrap(),
            Some(Ipv4Addr::new(10, 0, 0, 10)),
            Some(Ipv4Addr::new(10, 0, 0, 1)),
        )
    }

    fn found(ip: [u8; 4], kind: FindingKind) -> Event {
        Event::Found(Finding {
            ip: ip.into(),
            source: "test",
            kind,
        })
    }

    #[test]
    fn merges_findings_into_one_device() {
        let mut inv = inv();
        let now = SystemTime::UNIX_EPOCH;
        inv.apply(found([10, 0, 0, 1], FindingKind::Cached), now);
        inv.apply(
            found([10, 0, 0, 1], FindingKind::Mac("AA:BB:CC:00:11:22".into())),
            now,
        );
        inv.apply(found([10, 0, 0, 1], FindingKind::OpenPort(443)), now);
        assert_eq!(inv.devices.len(), 1);
        let d = &inv.devices[&Ipv4Addr::new(10, 0, 0, 1)];
        assert!(d.is_gateway && !d.is_self);
        assert!(
            !d.responding,
            "a stale cache entry and a MAC are not a response"
        );
        assert_eq!(d.mac.as_deref(), Some("AA:BB:CC:00:11:22"));
        assert!(d.open_ports.contains(&443));
        assert_eq!(d.evidence.len(), 3);
    }

    #[test]
    fn tailnet_peers_link_by_self_and_unique_hostname() {
        let mut inv = inv();
        let now = SystemTime::UNIX_EPOCH;
        inv.apply(
            found([10, 0, 0, 10], FindingKind::Responded("x".into())),
            now,
        );
        inv.apply(
            found(
                [10, 0, 0, 19],
                FindingKind::Name(NameSource::Mdns, "Retro.local".into()),
            ),
            now,
        );
        inv.apply(
            found(
                [10, 0, 0, 20],
                FindingKind::Name(NameSource::Dns, "twin.lan".into()),
            ),
            now,
        );
        inv.apply(
            found(
                [10, 0, 0, 21],
                FindingKind::Name(NameSource::Dns, "twin.lan".into()),
            ),
            now,
        );
        let peer = |id: &str, host: &str, is_self| Peer {
            id: id.into(),
            hostname: host.into(),
            dns_name: format!("{}.tail.ts.net", host.to_lowercase()),
            os: "linux".into(),
            ips: vec![],
            online: true,
            is_self,
            exit_node: false,
            shared_in: false,
            last_seen: None,
        };
        let peers = [
            peer("me", "atlas", true),
            peer("p", "retro", false),
            peer("t", "twin", false),
            peer("far", "cloud-vm", false),
        ];
        let links = link_tailnet(&peers, &inv.devices);
        assert_eq!(links.get("me"), Some(&Ipv4Addr::new(10, 0, 0, 10)));
        assert_eq!(links.get("p"), Some(&Ipv4Addr::new(10, 0, 0, 19)));
        assert_eq!(links.get("t"), None, "ambiguous names are not guessed");
        assert_eq!(links.get("far"), None);
        assert_eq!(plain_name("Atlas-(2).local"), "atlas");
    }

    #[test]
    fn tailnet_peers_are_probed_at_their_tailscale_address() {
        let mut inv = inv();
        let now = SystemTime::UNIX_EPOCH;
        inv.apply(
            found(
                [10, 0, 0, 5],
                FindingKind::Name(NameSource::Dns, "mediapc".into()),
            ),
            now,
        );
        let peer = |id: &str, host: &str, ip: [u8; 4], online, shared_in| Peer {
            id: id.into(),
            hostname: host.into(),
            dns_name: format!("{host}.tail.ts.net"),
            os: "windows".into(),
            ips: vec![Ipv4Addr::from(ip).into()],
            online,
            is_self: false,
            exit_node: false,
            shared_in,
            last_seen: None,
        };
        inv.apply(
            Event::Tailnet(vec![
                peer("b", "mediapc", [100, 64, 1, 1], true, false),
                peer("d", "camserver", [100, 64, 2, 1], true, false),
                peer("o", "offline", [100, 64, 2, 2], false, false),
                peer("s", "friends-nas", [100, 64, 2, 3], true, true),
            ]),
            now,
        );
        assert_eq!(
            probe_peers(&inv.tailnet, &inv.devices),
            vec![Ipv4Addr::new(100, 64, 2, 1)],
            "only camserver: mediapc is on the LAN, the rest are offline or not ours"
        );
        inv.apply(found([100, 64, 2, 1], FindingKind::OpenPort(32400)), now);
        let d = &inv.remote[&Ipv4Addr::new(100, 64, 2, 1)];
        assert!(d.open_ports.contains(&32400));
        assert_eq!(d.hostname.as_deref(), Some("camserver"));
        assert!(inv.devices.len() == 1 && inv.ignored_outside_subnet == 0);
    }

    #[test]
    fn counts_rather_than_keeps_outside_subnet() {
        let mut inv = inv();
        inv.apply(
            found([172, 17, 0, 2], FindingKind::Responded("x".into())),
            SystemTime::UNIX_EPOCH,
        );
        assert!(inv.devices.is_empty());
        assert_eq!(inv.ignored_outside_subnet, 1);
    }

    #[test]
    fn mdns_updates_the_same_instance_in_place() {
        let mut inv = inv();
        let svc = |port| MdnsService {
            service_type: "_http._tcp.local.".into(),
            instance: "printer".into(),
            host: "printer.local".into(),
            port,
            txt: BTreeMap::new(),
        };
        let now = SystemTime::UNIX_EPOCH;
        inv.apply(found([10, 0, 0, 5], FindingKind::Mdns(svc(80))), now);
        inv.apply(found([10, 0, 0, 5], FindingKind::Mdns(svc(8080))), now);
        let d = &inv.devices[&Ipv4Addr::new(10, 0, 0, 5)];
        assert_eq!(d.mdns_services.len(), 1);
        assert_eq!(d.mdns_services[0].port, 8080);
        assert!(d.responding);
    }

    #[test]
    fn status_updates_replace_and_cancel_marks_stopped() {
        let mut inv = inv();
        let now = SystemTime::UNIX_EPOCH;
        inv.apply(Event::Status("a", SourceState::Running("".into())), now);
        inv.apply(
            Event::Status("b", SourceState::Unavailable("no tool".into())),
            now,
        );
        inv.apply(Event::Status("a", SourceState::Failed("boom".into())), now);
        assert_eq!(inv.sources.len(), 2);
        assert!(inv.any_failed(), "unavailable is not a failure, failed is");
        inv.apply(Event::Status("c", SourceState::Running("".into())), now);
        inv.stop_running();
        assert_eq!(inv.sources[2].1, SourceState::Stopped);
        assert_eq!(inv.sources[1].1, SourceState::Unavailable("no tool".into()));
    }
}
