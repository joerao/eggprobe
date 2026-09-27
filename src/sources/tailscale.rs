//! Devices on the user's tailnet, from the local Tailscale daemon. Reading
//! `tailscale status --json` sends nothing over the network and needs no
//! privileges.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde_json::Value;
use tokio::process::Command;

use super::Sink;
use crate::inventory::{SourceState, rfc3339_opt};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Peer {
    pub id: String,
    /// The machine's own hostname, as Tailscale reports it.
    pub hostname: String,
    /// MagicDNS name, without the trailing dot.
    pub dns_name: String,
    pub os: String,
    pub ips: Vec<IpAddr>,
    pub online: bool,
    pub is_self: bool,
    pub exit_node: bool,
    /// Shared into this tailnet from someone else's; not probed.
    pub shared_in: bool,
    #[serde(serialize_with = "rfc3339_opt")]
    pub last_seen: Option<SystemTime>,
}

impl Peer {
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ips.iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
    }

    /// The MagicDNS name's first label, which is what people call it.
    pub fn short_name(&self) -> &str {
        let first = self.dns_name.split('.').next().unwrap_or("");
        if first.is_empty() {
            &self.hostname
        } else {
            first
        }
    }
}

pub async fn run(sink: &Sink) -> Vec<Peer> {
    sink.status(SourceState::Running("reading tailscale status".into()));
    let output = tokio::time::timeout(
        Duration::from_secs(5),
        Command::new("tailscale")
            .args(["status", "--json"])
            .output(),
    )
    .await;
    let output = match output {
        Err(_) => {
            sink.status(SourceState::Unavailable(
                "tailscale did not answer within 5 s".into(),
            ));
            return Vec::new();
        }
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => {
            sink.status(SourceState::Unavailable(
                "tailscale is not installed".into(),
            ));
            return Vec::new();
        }
        Ok(Err(e)) => {
            sink.status(SourceState::Unavailable(format!(
                "could not run tailscale: {e}"
            )));
            return Vec::new();
        }
        Ok(Ok(out)) => out,
    };
    let json: Value = match serde_json::from_slice(&output.stdout) {
        Ok(v) => v,
        Err(_) => {
            let err = String::from_utf8_lossy(&output.stderr);
            let reason = err
                .lines()
                .next()
                .unwrap_or("no status output")
                .trim()
                .to_string();
            sink.status(SourceState::Unavailable(format!("tailscale: {reason}")));
            return Vec::new();
        }
    };
    match parse(&json) {
        Ok(peers) => {
            let online = peers.iter().filter(|p| p.online && !p.is_self).count();
            let others = peers.iter().filter(|p| !p.is_self).count();
            sink.status(SourceState::Done(format!(
                "{others} peers, {online} online"
            )));
            peers
        }
        Err(reason) => {
            sink.status(SourceState::Unavailable(reason));
            Vec::new()
        }
    }
}

/// This machine first, then peers by name.
fn parse(json: &Value) -> Result<Vec<Peer>, String> {
    let state = json["BackendState"].as_str().unwrap_or("unknown");
    if state != "Running" {
        return Err(format!("tailscale is not connected (state: {state})"));
    }
    let mut peers = Vec::new();
    if let Some(me) = json.get("Self").and_then(|v| peer(v, true)) {
        peers.push(me);
    }
    if let Some(map) = json["Peer"].as_object() {
        let mut others: Vec<Peer> = map.values().filter_map(|v| peer(v, false)).collect();
        others.sort_by_key(|p| p.short_name().to_lowercase());
        peers.extend(others);
    }
    Ok(peers)
}

fn peer(v: &Value, is_self: bool) -> Option<Peer> {
    let s = |key: &str| v[key].as_str().unwrap_or("").to_string();
    let ips = v["TailscaleIPs"]
        .as_array()?
        .iter()
        .filter_map(|ip| ip.as_str()?.parse().ok())
        .collect();
    Some(Peer {
        id: s("ID"),
        hostname: s("HostName"),
        dns_name: s("DNSName").trim_end_matches('.').to_string(),
        os: s("OS"),
        ips,
        online: is_self || v["Online"].as_bool().unwrap_or(false),
        is_self,
        exit_node: v["ExitNode"].as_bool().unwrap_or(false),
        shared_in: v["ShareeNode"].as_bool().unwrap_or(false),
        last_seen: v["LastSeen"]
            .as_str()
            .and_then(|t| humantime::parse_rfc3339_weak(t).ok())
            // Tailscale reports the zero time for peers it has never seen.
            .filter(|t| {
                t.duration_since(SystemTime::UNIX_EPOCH)
                    .is_ok_and(|d| d.as_secs() > 0)
            }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn status() -> Value {
        json!({
            "BackendState": "Running",
            "Self": {
                "ID": "n1", "HostName": "atlas", "DNSName": "atlas.tail1234.ts.net.",
                "OS": "linux", "TailscaleIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
                "Online": true, "LastSeen": "0001-01-01T00:00:00Z"
            },
            "Peer": {
                "k2": {
                    "ID": "n2", "HostName": "iPhone", "DNSName": "phone.tail1234.ts.net.",
                    "OS": "iOS", "TailscaleIPs": ["100.64.0.2"], "Online": false,
                    "LastSeen": "2026-09-20T10:00:00Z", "ExitNode": false
                },
                "k3": {
                    "ID": "n3", "HostName": "Orion", "DNSName": "orion.tail1234.ts.net.",
                    "OS": "windows", "TailscaleIPs": ["100.64.0.3"], "Online": true,
                    "ExitNode": true, "ShareeNode": true
                }
            }
        })
    }

    #[test]
    fn parses_self_first_then_peers_by_name() {
        let peers = parse(&status()).unwrap();
        let names: Vec<&str> = peers.iter().map(|p| p.short_name()).collect();
        assert_eq!(names, ["atlas", "orion", "phone"]);
        assert!(peers[0].is_self && peers[0].online);
        assert_eq!(peers[0].ipv4(), Some(Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(peers[0].last_seen, None, "zero time means never");
        assert!(peers[1].exit_node && peers[1].shared_in);
        assert!(!peers[2].shared_in);
        assert!(!peers[2].online);
        assert!(peers[2].last_seen.is_some());
    }

    #[test]
    fn a_stopped_daemon_is_unavailable_not_empty() {
        let err = parse(&json!({"BackendState": "Stopped"})).unwrap_err();
        assert!(err.contains("Stopped"));
    }
}
