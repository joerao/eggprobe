//! The kernel's neighbor (ARP) table. Reading it needs no privileges, and after
//! a TCP sweep it holds MACs for every host that answered ARP, including hosts
//! that drop all TCP.

use std::net::Ipv4Addr;

use tokio::process::Command;

use super::Sink;
use crate::inventory::{FindingKind, SourceState};

#[derive(Debug, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: String,
    /// The kernel confirmed the entry recently. Stale entries may belong to
    /// hosts that have since left.
    pub reachable: bool,
}

/// Reads the table and reports it. Returns the neighbors so the caller can
/// decide which hosts deserve a port probe.
pub async fn read(sink: &Sink, interface: Option<&str>, pass: &str) -> Vec<Neighbor> {
    sink.status(SourceState::Running(format!("{pass} read")));
    let (neighbors, how) = match table(interface).await {
        Ok(found) => found,
        Err(reason) => {
            sink.status(SourceState::Unavailable(reason));
            return Vec::new();
        }
    };
    for n in &neighbors {
        sink.found(n.ip, FindingKind::Mac(n.mac.clone()));
        let kind = if n.reachable {
            FindingKind::Responded("neighbor entry reachable".into())
        } else {
            FindingKind::Cached
        };
        sink.found(n.ip, kind);
    }
    let reachable = neighbors.iter().filter(|n| n.reachable).count();
    sink.status(SourceState::Done(format!(
        "{} entries, {reachable} reachable, via {how}",
        neighbors.len()
    )));
    neighbors
}

async fn table(interface: Option<&str>) -> Result<(Vec<Neighbor>, &'static str), String> {
    if cfg!(target_os = "linux") {
        let mut args = vec!["-4", "neigh", "show"];
        if let Some(i) = interface {
            args.extend(["dev", i]);
        }
        if let Ok(out) = Command::new("ip").args(&args).output().await
            && out.status.success()
        {
            return Ok((
                parse_ip_neigh(&String::from_utf8_lossy(&out.stdout)),
                "ip neigh",
            ));
        }
        // Without iproute2 the proc table still has MACs, but no freshness.
        return match tokio::fs::read_to_string("/proc/net/arp").await {
            Ok(text) => Ok((parse_proc_arp(&text, interface), "/proc/net/arp")),
            Err(e) => Err(format!(
                "neither `ip neigh` nor /proc/net/arp is readable: {e}"
            )),
        };
    }
    let mut args = vec!["-an"];
    if let Some(i) = interface {
        args.extend(["-i", i]);
    }
    match Command::new("arp").args(&args).output().await {
        Ok(out) if out.status.success() => Ok((
            parse_bsd_arp(&String::from_utf8_lossy(&out.stdout)),
            "arp -an",
        )),
        Ok(out) => Err(format!(
            "arp -an failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => Err(format!("arp is not available: {e}")),
    }
}

/// `10.0.0.1 lladdr aa:bb:cc:dd:ee:ff router REACHABLE`, optionally with
/// `dev eth0` after the address.
fn parse_ip_neigh(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ip = tokens.first()?.parse().ok()?;
            let at = tokens.iter().position(|t| *t == "lladdr")?;
            let mac = normalize_mac(tokens.get(at + 1)?)?;
            let reachable = match *tokens.last()? {
                "REACHABLE" | "DELAY" | "PROBE" => true,
                "STALE" | "PERMANENT" | "NOARP" => false,
                _ => return None,
            };
            Some(Neighbor { ip, mac, reachable })
        })
        .collect()
}

/// `/proc/net/arp`: address, hw type, flags, hw address, mask, device.
fn parse_proc_arp(text: &str, interface: Option<&str>) -> Vec<Neighbor> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() < 6 || interface.is_some_and(|i| i != cols[5]) {
                return None;
            }
            let flags = u32::from_str_radix(cols[2].trim_start_matches("0x"), 16).ok()?;
            if flags & 0x2 == 0 {
                return None;
            }
            Some(Neighbor {
                ip: cols[0].parse().ok()?,
                mac: normalize_mac(cols[3])?,
                reachable: false,
            })
        })
        .collect()
}

/// macOS / BSD: `? (10.0.0.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]`.
fn parse_bsd_arp(text: &str) -> Vec<Neighbor> {
    text.lines()
        .filter_map(|line| {
            let open = line.find('(')?;
            let close = line.find(')')?;
            let ip = line.get(open + 1..close)?.parse().ok()?;
            let rest = line.get(close + 1..)?.trim_start().strip_prefix("at ")?;
            let mac = normalize_mac(rest.split_whitespace().next()?)?;
            Some(Neighbor {
                ip,
                mac,
                reachable: false,
            })
        })
        .collect()
}

/// Uppercase, colon-separated, zero-padded. Rejects the all-zero and broadcast
/// addresses the kernel uses as placeholders.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut octets = [0u8; 6];
    for (o, p) in octets.iter_mut().zip(&parts) {
        *o = u8::from_str_radix(p, 16).ok()?;
    }
    if octets == [0; 6] || octets == [0xff; 6] {
        return None;
    }
    Some(
        octets
            .iter()
            .map(|o| format!("{o:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_neigh_keeps_states_honestly() {
        let text = "\
10.0.0.1 lladdr 10:0c:6b:00:00:01 router REACHABLE
10.0.0.20 dev wlan0 lladdr b8:27:eb:01:02:03 STALE
10.0.0.30 FAILED
10.0.0.31 lladdr 00:00:00:00:00:00 INCOMPLETE
10.0.0.40 lladdr dc:a6:32:aa:bb:cc DELAY
";
        let n = parse_ip_neigh(text);
        assert_eq!(n.len(), 3);
        assert_eq!(n[0].mac, "10:0C:6B:00:00:01");
        assert!(n[0].reachable);
        assert!(!n[1].reachable);
        assert_eq!(n[2].ip, Ipv4Addr::new(10, 0, 0, 40));
    }

    #[test]
    fn proc_arp_skips_incomplete_and_other_interfaces() {
        let text = "\
IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1      0x1         0x2         10:0c:6b:00:00:01     *        eth0
10.0.0.9      0x1         0x0         00:00:00:00:00:00     *        eth0
172.17.0.2       0x1         0x2         02:42:ac:11:00:02     *        docker0
";
        let n = parse_proc_arp(text, Some("eth0"));
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].ip, Ipv4Addr::new(10, 0, 0, 1));
        assert!(!n[0].reachable);
    }

    #[test]
    fn bsd_arp_pads_short_octets() {
        let text = "\
? (10.0.0.1) at 0:1b:63:a:b:c on en0 ifscope [ethernet]
? (10.0.0.7) at (incomplete) on en0 ifscope [ethernet]
";
        let n = parse_bsd_arp(text);
        assert_eq!(n.len(), 1);
        assert_eq!(n[0].mac, "00:1B:63:0A:0B:0C");
    }

    #[test]
    fn normalize_rejects_placeholders() {
        assert_eq!(normalize_mac("ff:ff:ff:ff:ff:ff"), None);
        assert_eq!(
            normalize_mac("aa-bb-cc-dd-ee-ff").as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(normalize_mac("aa:bb:cc"), None);
    }
}
