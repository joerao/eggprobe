//! TCP connect probes. No privileges needed: an accepted connection means an
//! open port, and a refusal still proves the host is there.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;

use super::{Cancel, Sink, cancelled};
use crate::inventory::{FindingKind, SourceState};

/// Ports tried on every address to find live hosts. 62078 is iOS's lockdown
/// service, which answers on phones that expose nothing else.
pub const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 62078];

/// Ports tried on hosts known to be alive: common services plus homelab and
/// IoT signatures.
pub const SIGNATURE_PORTS: &[u16] = &[
    21, 22, 23, 53, 80, 81, 135, 139, 443, 445, 515, 554, 631, 1400, 1880, 1883, 3000, 3389, 5000,
    5001, 5357, 6053, 6668, 7000, 8000, 8006, 8008, 8009, 8060, 8080, 8096, 8123, 8443, 8581, 8883,
    8888, 9000, 9090, 9100, 9443, 10000, 32400, 49152, 51826, 62078,
];

/// Well under the usual 1024 descriptor limit.
const CONCURRENCY: usize = 256;

/// How hard to push. A sweep fans out across every address; a port probe
/// hits few hosts with many ports, so it caps connections per host to stay
/// under consumer devices' SYN-flood protection.
pub struct Pace {
    pub timeout: Duration,
    pub per_host: usize,
    /// Delay between starting successive hosts. Each first connection to a
    /// new address makes the kernel broadcast ARP; a burst of hundreds at
    /// once gets throttled or lost on Wi-Fi, so the sweep spreads them out.
    pub stagger: Duration,
}

/// The first connection waits on ARP, which can take over a second on Wi-Fi.
pub const SWEEP: Pace = Pace {
    timeout: Duration::from_millis(1500),
    per_host: usize::MAX,
    stagger: Duration::from_millis(4),
};

/// Tailnet peers are often reached through a relay (DERP), which adds tens
/// of milliseconds each way; there is no ARP, and the relay needs no pacing.
pub const TAILNET: Pace = Pace {
    timeout: Duration::from_millis(2000),
    per_host: 8,
    stagger: Duration::ZERO,
};

/// By now ARP has resolved, so a silent port is filtered, not slow.
pub const PORTS: Pace = Pace {
    timeout: Duration::from_millis(1000),
    per_host: 8,
    stagger: Duration::ZERO,
};

enum Outcome {
    Open,
    Refused,
    Silent,
}

async fn connect(ip: Ipv4Addr, port: u16, limit: Duration) -> Outcome {
    match timeout(limit, TcpStream::connect(SocketAddr::from((ip, port)))).await {
        Ok(Ok(_)) => Outcome::Open,
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => Outcome::Refused,
        _ => Outcome::Silent,
    }
}

/// Probes every (host, port) pair and reports what answered. Returns the
/// number of hosts that responded.
pub async fn probe(
    sink: &Sink,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    pace: &Pace,
    label: &str,
    cancel: &mut Cancel,
) -> usize {
    let total = hosts.len() * ports.len();
    sink.status(SourceState::Running(format!(
        "{label}: {} hosts × {} ports",
        hosts.len(),
        ports.len()
    )));
    let limit = Arc::new(Semaphore::new(CONCURRENCY));
    let per_host: Vec<Arc<Semaphore>> = hosts
        .iter()
        .map(|_| Arc::new(Semaphore::new(pace.per_host.min(Semaphore::MAX_PERMITS))))
        .collect();
    let open = Arc::new(AtomicUsize::new(0));
    let wait = pace.timeout;
    let mut tasks = JoinSet::new();
    // Port-major order spreads the in-flight connections across hosts.
    for &port in ports {
        for (i, (&ip, host_limit)) in hosts.iter().zip(&per_host).enumerate() {
            let (sink, limit, host_limit, open) = (
                sink.clone(),
                limit.clone(),
                host_limit.clone(),
                open.clone(),
            );
            let start = pace.stagger * i as u32;
            tasks.spawn(async move {
                tokio::time::sleep(start).await;
                let Ok(_host) = host_limit.acquire().await else {
                    return None;
                };
                let Ok(_permit) = limit.acquire().await else {
                    return None;
                };
                match connect(ip, port, wait).await {
                    Outcome::Open => {
                        open.fetch_add(1, Ordering::Relaxed);
                        sink.found(ip, FindingKind::Responded(format!("TCP {port} accepted")));
                        sink.found(ip, FindingKind::OpenPort(port));
                        Some(ip)
                    }
                    Outcome::Refused => {
                        sink.found(ip, FindingKind::Responded(format!("TCP {port} refused")));
                        Some(ip)
                    }
                    Outcome::Silent => None,
                }
            });
        }
    }
    let mut responded = std::collections::BTreeSet::new();
    let mut done = 0;
    sink.progress(0, total);
    loop {
        let result = tokio::select! {
            r = tasks.join_next() => r,
            _ = cancelled(cancel) => {
                tasks.abort_all();
                sink.status(SourceState::Stopped);
                return responded.len();
            }
        };
        let Some(result) = result else { break };
        if let Ok(Some(ip)) = result {
            responded.insert(ip);
        }
        done += 1;
        if done % 16 == 0 || done == total {
            sink.progress(done, total);
        }
    }
    sink.status(SourceState::Done(format!(
        "{label}: {total} probes, {} hosts responded, {} open ports",
        responded.len(),
        open.load(Ordering::Relaxed)
    )));
    responded.len()
}
