//! Hostnames, asked for three ways at once for every known host:
//!
//! - reverse DNS through the router, which usually knows the name each device
//!   gave its DHCP server, which covers most hosts on a home network;
//! - NetBIOS node status, which every Windows PC (and Samba) answers with its
//!   computer name and workgroup;
//! - a PTR query sent straight to the device's mDNS responder (Apple, Linux
//!   and many IoT devices), which works even when multicast browsing misses it.
//!
//! All unicast, all unprivileged, a few packets per host.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};

use super::wire::{self, NetBios};
use super::{Cancel, Sink, cancelled};
use crate::inventory::{FindingKind, NameSource, SourceState};

const TIMEOUT: Duration = Duration::from_millis(1000);
const CONCURRENCY: usize = 48;

pub async fn run(sink: &Sink, hosts: &[Ipv4Addr], dns: &[Ipv4Addr], cancel: &mut Cancel) {
    sink.status(SourceState::Running(format!(
        "asking {} hosts by reverse DNS, NetBIOS and mDNS",
        hosts.len()
    )));
    let limit = Arc::new(Semaphore::new(CONCURRENCY));
    let counts = Arc::new([
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ]);
    let dns: Arc<[Ipv4Addr]> = dns.into();
    let mut tasks = JoinSet::new();
    for &ip in hosts {
        let (sink, limit, counts, dns) = (sink.clone(), limit.clone(), counts.clone(), dns.clone());
        tasks.spawn(async move {
            let Ok(_permit) = limit.acquire().await else {
                return false;
            };
            let (by_dns, by_netbios, by_mdns) =
                tokio::join!(reverse_dns(ip, &dns), netbios(ip), mdns_ptr(ip));
            let mut named = false;
            if let Some(name) = by_dns {
                counts[0].fetch_add(1, Ordering::Relaxed);
                sink.found(ip, FindingKind::Name(NameSource::Dns, name));
                named = true;
            }
            if let Some(NetBios { name, workgroup }) = by_netbios {
                counts[1].fetch_add(1, Ordering::Relaxed);
                sink.found(ip, FindingKind::Responded("answered NetBIOS".into()));
                sink.found(ip, FindingKind::Name(NameSource::Netbios, name));
                if let Some(group) = workgroup {
                    sink.found(ip, FindingKind::Workgroup(group));
                }
                named = true;
            }
            if let Some(name) = by_mdns {
                counts[2].fetch_add(1, Ordering::Relaxed);
                sink.found(ip, FindingKind::Responded("answered mDNS".into()));
                sink.found(ip, FindingKind::Name(NameSource::Mdns, name));
                named = true;
            }
            named
        });
    }
    let (mut done, mut named) = (0, 0);
    sink.progress(0, hosts.len());
    loop {
        let next = tokio::select! {
            r = tasks.join_next() => r,
            _ = cancelled(cancel) => {
                tasks.abort_all();
                sink.status(SourceState::Stopped);
                return;
            }
        };
        let Some(result) = next else { break };
        done += 1;
        named += usize::from(result.unwrap_or(false));
        sink.progress(done, hosts.len());
    }
    let c = |i: usize| counts[i].load(Ordering::Relaxed);
    sink.status(SourceState::Done(format!(
        "{named} of {} hosts named · reverse DNS {}, NetBIOS {}, mDNS {}",
        hosts.len(),
        c(0),
        c(1),
        c(2)
    )));
}

/// Asks each server in turn until one answers, named or not.
async fn reverse_dns(ip: Ipv4Addr, servers: &[Ipv4Addr]) -> Option<String> {
    for &server in servers {
        let id = query_id(ip, 0);
        let query = wire::ptr_query(id, ip, true);
        if let Some(names) =
            exchange((server, 53).into(), &query, |r| wire::ptr_answers(r, id)).await
        {
            return names.into_iter().find(|n| useful(n, ip));
        }
    }
    None
}

async fn netbios(ip: Ipv4Addr) -> Option<NetBios> {
    let id = query_id(ip, 1);
    let answer = exchange((ip, 137).into(), &wire::nbstat_query(id), |r| {
        wire::nbstat_answer(r, id)
    })
    .await?;
    useful(&answer.name, ip).then_some(answer)
}

async fn mdns_ptr(ip: Ipv4Addr) -> Option<String> {
    let id = query_id(ip, 2);
    let query = wire::ptr_query(id, ip, false);
    let names = exchange((ip, 5353).into(), &query, |r| wire::ptr_answers(r, id)).await?;
    names
        .into_iter()
        .map(|n| n.strip_suffix(".local").map(str::to_string).unwrap_or(n))
        .find(|n| useful(n, ip))
}

/// Sends one datagram and waits for a reply that `parse` accepts, ignoring
/// strays, until the timeout.
async fn exchange<T>(
    to: SocketAddr,
    packet: &[u8],
    parse: impl Fn(&[u8]) -> Option<T>,
) -> Option<T> {
    let socket = UdpSocket::bind(("0.0.0.0", 0)).await.ok()?;
    socket.send_to(packet, to).await.ok()?;
    let deadline = Instant::now() + TIMEOUT;
    let mut buf = [0u8; 1500];
    loop {
        let (len, from) = timeout_at(deadline, socket.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        if from.ip() == to.ip()
            && let Some(parsed) = parse(&buf[..len])
        {
            return Some(parsed);
        }
    }
}

/// Distinct per host and protocol, so replies can't be mistaken for another's.
fn query_id(ip: Ipv4Addr, protocol: u16) -> u16 {
    let [.., c, d] = ip.octets();
    u16::from_be_bytes([c, d])
        .wrapping_mul(3)
        .wrapping_add(protocol)
}

/// Rejects names that say nothing: the address itself spelled out
/// (`10-0-0-5`, `host-5.lan`), or `localhost`.
fn useful(name: &str, ip: Ipv4Addr) -> bool {
    let first = name.split('.').next().unwrap_or("").to_lowercase();
    if first.is_empty() || first == "localhost" {
        return false;
    }
    let [a, b, c, d] = ip.octets();
    let spelled = [
        format!("{a}-{b}-{c}-{d}"),
        format!("{d}-{c}-{b}-{a}"),
        format!("{a}.{b}.{c}.{d}"),
    ];
    !spelled.iter().any(|s| name.contains(s.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn useless_names_are_dropped() {
        let ip = Ipv4Addr::new(10, 0, 0, 5);
        assert!(useful("tower.home.example.net", ip));
        assert!(useful("TOWER", ip));
        assert!(!useful("10-0-0-5.lan", ip));
        assert!(!useful("dhcp-5-0-0-10.example.net", ip));
        assert!(!useful("localhost", ip));
        assert!(!useful("", ip));
    }

    #[test]
    fn ids_differ_by_protocol_and_host() {
        let a = Ipv4Addr::new(10, 0, 0, 5);
        let b = Ipv4Addr::new(10, 0, 0, 6);
        assert_ne!(query_id(a, 0), query_id(a, 1));
        assert_ne!(query_id(a, 0), query_id(b, 0));
    }

    #[tokio::test]
    async fn silence_is_none_not_an_error() {
        // TEST-NET-1: guaranteed not to answer.
        let ip = Ipv4Addr::new(192, 0, 2, 1);
        let started = Instant::now();
        assert_eq!(netbios(ip).await, None);
        assert!(started.elapsed() < TIMEOUT + Duration::from_millis(500));
    }
}
