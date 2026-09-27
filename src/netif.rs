//! Choosing the interface and subnet to scan.

use std::net::Ipv4Addr;

use anyhow::{Context, Result, anyhow, bail};
use ipnet::Ipv4Net;
use serde::Serialize;

/// Sweeping more addresses than this takes minutes and is rarely what was meant.
pub const MAX_HOSTS: usize = 4096;

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub interface: Option<String>,
    pub address: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    /// Where to ask for reverse DNS: the gateway (home routers answer for
    /// their DHCP clients), then the interface's configured resolvers.
    pub dns: Vec<Ipv4Addr>,
    pub subnet: Ipv4Net,
}

/// Resolves the scan target. An explicit subnet wins; otherwise the subnet of
/// the named interface, or of the default-route interface.
pub fn resolve(interface: Option<&str>, subnet: Option<Ipv4Net>) -> Result<Target> {
    let iface = match interface {
        Some(name) => Some(
            netdev::get_interfaces()
                .into_iter()
                .find(|i| i.name == name)
                .ok_or_else(|| anyhow!("no interface named {name:?}"))?,
        ),
        None => netdev::get_default_interface().ok(),
    };

    let address = iface
        .as_ref()
        .and_then(|i| i.ipv4.first())
        .map(|n| n.addr());
    let gateway = iface
        .as_ref()
        .and_then(|i| i.gateway.as_ref())
        .and_then(|g| g.ipv4.first().copied());

    let subnet = match subnet {
        Some(s) => s.trunc(),
        None => iface
            .as_ref()
            .and_then(|i| i.ipv4.first())
            .map(|n| n.trunc())
            .context("no IPv4 interface with a default route; pass --subnet")?,
    };
    check_size(subnet)?;

    let mut dns: Vec<Ipv4Addr> = gateway.into_iter().collect();
    for server in iface.iter().flat_map(|i| &i.dns_servers) {
        if let std::net::IpAddr::V4(v4) = server
            && !dns.contains(v4)
        {
            dns.push(*v4);
        }
    }

    Ok(Target {
        interface: iface.map(|i| i.name),
        address,
        gateway,
        dns,
        subnet,
    })
}

fn check_size(subnet: Ipv4Net) -> Result<()> {
    let hosts = host_count(subnet);
    if hosts > MAX_HOSTS {
        bail!(
            "{subnet} has {hosts} addresses; eggprobe sweeps at most {MAX_HOSTS}. \
             Pass a smaller --subnet, such as a /24"
        );
    }
    Ok(())
}

pub fn host_count(subnet: Ipv4Net) -> usize {
    subnet.hosts().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_subnets() {
        assert!(check_size("10.0.0.0/24".parse().unwrap()).is_ok());
        assert!(check_size("10.0.0.0/20".parse().unwrap()).is_ok());
        assert!(check_size("10.0.0.0/16".parse().unwrap()).is_err());
    }

    #[test]
    fn explicit_subnet_is_normalized() {
        let t = resolve(None, Some("127.0.0.9/30".parse().unwrap())).unwrap();
        assert_eq!(t.subnet.to_string(), "127.0.0.8/30");
    }
}
