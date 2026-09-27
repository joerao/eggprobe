//! Human names for what the sources report. Display only: these say what a
//! device offers, not what it is. That is the classifier's job.

use crate::inventory::Device;

/// A friendly label for an mDNS service type, or None to leave it out of
/// summaries (plumbing types every Apple device advertises, for instance).
pub fn service(ty: &str) -> Option<&'static str> {
    let short = ty.trim_end_matches('.').trim_end_matches(".local");
    Some(match short {
        "_airplay._tcp" | "_raop._tcp" => "AirPlay",
        "_googlecast._tcp" => "Cast",
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => "Printer",
        "_uscan._tcp" | "_uscans._tcp" | "_scanner._tcp" => "Scanner",
        "_hap._tcp" | "_hap._udp" | "_homekit._tcp" => "HomeKit",
        "_matter._tcp" | "_matterc._udp" | "_matter._udp" => "Matter",
        "_meshcop._udp" | "_trel._udp" | "_srpl-tls._tcp" => "Thread",
        "_ssh._tcp" | "_sftp-ssh._tcp" => "SSH",
        "_smb._tcp" => "SMB",
        "_afpovertcp._tcp" => "AFP",
        "_nfs._tcp" => "NFS",
        "_ftp._tcp" => "FTP",
        "_http._tcp" | "_https._tcp" => "Web",
        "_spotify-connect._tcp" => "Spotify",
        "_sonos._tcp" => "Sonos",
        "_amzn-wplay._tcp" | "_amzn-alexa._tcp" => "Amazon",
        "_workstation._tcp" => "Workstation",
        "_home-assistant._tcp" => "Home Assistant",
        "_esphomelib._tcp" => "ESPHome",
        "_hue._tcp" => "Hue",
        "_wled._tcp" => "WLED",
        "_mqtt._tcp" => "MQTT",
        "_homebridge._tcp" => "Homebridge",
        "_shelly._tcp" => "Shelly",
        "_hubitat._tcp" => "Hubitat",
        "_octoprint._tcp" => "OctoPrint",
        "_plex._tcp" | "_plexmediasvr._tcp" => "Plex",
        "_jellyfin._tcp" => "Jellyfin",
        "_roku-rcp._tcp" => "Roku",
        "_rtsp._tcp" => "RTSP",
        "_daap._tcp" | "_dacp._tcp" | "_touch-able._tcp" => "iTunes",
        "_nvstream._tcp" => "GameStream",
        "_rdlink._tcp" | "_companion-link._tcp" | "_device-info._tcp" | "_sleep-proxy._udp" => {
            return None;
        }
        _ => return None,
    })
}

/// The protocol conventionally on a port, for chips in the detail view.
pub fn port(port: u16) -> Option<&'static str> {
    Some(match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        53 => "dns",
        80 | 81 | 3000 | 5000 | 5001 | 8000 | 8080 | 8888 | 9000 => "http",
        135 => "msrpc",
        139 => "netbios",
        443 | 8443 => "https",
        445 => "smb",
        515 => "lpd",
        554 => "rtsp",
        631 => "ipp",
        1400 => "sonos",
        1880 => "node-red",
        1883 => "mqtt",
        3389 => "rdp",
        5357 => "wsd",
        6053 => "esphome",
        6668 => "tuya",
        7000 => "airplay",
        8006 => "proxmox",
        8008 | 8009 => "cast",
        8060 => "roku",
        8096 => "jellyfin",
        8123 => "home-assistant",
        8581 => "homebridge",
        8883 => "mqtts",
        9090 => "prometheus",
        9100 => "jetdirect",
        9443 => "portainer",
        10000 => "webmin",
        32400 => "plex",
        49152 => "upnp",
        51826 => "homebridge",
        62078 => "apple-sync",
        _ => return None,
    })
}

/// The best name available: the name the device reports for itself, an mDNS
/// instance name from a service that names the device, then the hostname.
pub fn name(d: &Device) -> Option<String> {
    if let Some(n) = d.info.iter().find_map(|i| i.name.clone()) {
        return Some(n);
    }
    let preferred = [
        "_airplay._tcp.local.",
        "_googlecast._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_printer._tcp.local.",
        "_hap._tcp.local.",
        "_raop._tcp.local.",
        "_companion-link._tcp.local.",
    ];
    let from_mdns = preferred
        .iter()
        .find_map(|ty| d.mdns_services.iter().find(|s| s.service_type == *ty))
        .map(|s| clean_instance(&s.instance));
    from_mdns
        .filter(|n| !n.is_empty())
        .or_else(|| d.hostname.clone())
        .or_else(|| {
            d.mdns_services
                .iter()
                .map(|s| clean_instance(&s.instance))
                .find(|n| !n.is_empty())
        })
}

/// The name to show, and whether it is a real name (true) or a description
/// standing in for one (false), which the list draws dimmer.
pub fn display_name(r: &super::Row) -> (String, bool) {
    if let Some(n) = name(&r.device) {
        return (n, true);
    }
    if let Some(p) = &r.peer {
        return (p.short_name().to_string(), true);
    }
    // A product only stands in for a name when the evidence is solid; a
    // single weak hint ("port 9443 is open") must not become a label.
    if let Some(product) = &r.class.product
        && matches!(
            r.class.confidence,
            crate::classify::Confidence::Confident | crate::classify::Confidence::Likely
        )
    {
        return (product.clone(), false);
    }
    // The vendor has its own column, so it does not stand in here.
    ("Unnamed".into(), false)
}

/// A link to the service on a device's port: its DNS or mDNS name when it
/// has a usable one, so name-based virtual hosts and certificates work, and
/// its address otherwise.
pub fn url(d: &Device, port: u16) -> String {
    use crate::inventory::NameSource;
    let usable = |n: &str| {
        !n.is_empty()
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    };
    let dns = d
        .names
        .get(&NameSource::Dns)
        .map(|n| n.trim_end_matches('.'));
    let mdns = d.names.get(&NameSource::Mdns).map(|n| {
        let n = n.trim_end_matches('.');
        if n.ends_with(".local") {
            n.to_string()
        } else {
            format!("{n}.local")
        }
    });
    let host = match (dns, mdns) {
        (Some(n), _) if usable(n) && n.contains('.') => n.to_string(),
        (_, Some(n)) if usable(&n) => n,
        _ => d.ip.to_string(),
    };
    let scheme = match port {
        443 | 5001 | 8006 | 8443 | 9443 => "https",
        _ => self::port(port)
            .filter(|s| matches!(*s, "ssh" | "ftp" | "telnet" | "smb" | "rtsp"))
            .unwrap_or("http"),
    };
    match (scheme, port) {
        ("http", 80)
        | ("https", 443)
        | ("ssh", 22)
        | ("ftp", 21)
        | ("telnet", 23)
        | ("smb", 445)
        | ("rtsp", 554) => format!("{scheme}://{host}/"),
        _ => format!("{scheme}://{host}:{port}/"),
    }
}

/// `70-35-60-63.1 Living Room` → `Living Room`; RAOP names carry a MAC prefix.
fn clean_instance(instance: &str) -> String {
    match instance.split_once('@') {
        Some((mac, rest)) if mac.chars().all(|c| c.is_ascii_hexdigit()) => rest.to_string(),
        _ => instance.to_string(),
    }
}

/// Distinct service labels, in first-seen order, for the device list:
/// advertised services, then servers that described themselves.
pub fn services(d: &Device) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    let described = d.info.iter().filter_map(|i| match i.protocol {
        "plex" => Some("Plex"),
        "jellyfin" => Some("Jellyfin"),
        "emby" => Some("Emby"),
        "wled" => Some("WLED"),
        _ => None,
    });
    for label in d
        .mdns_services
        .iter()
        .filter_map(|s| service(&s.service_type))
        .chain(described)
    {
        if !out.contains(&label) {
            out.push(label);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::MdnsService;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::SystemTime;

    fn device() -> Device {
        Device {
            ip: "10.0.0.9".parse().unwrap(),
            mac: None,
            hostname: Some("host-9".into()),
            names: Default::default(),
            workgroup: None,
            responding: true,
            is_self: false,
            is_gateway: false,
            open_ports: BTreeSet::new(),
            mdns_services: Vec::new(),
            info: Vec::new(),
            evidence: BTreeSet::new(),
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }

    fn svc(ty: &str, instance: &str) -> MdnsService {
        MdnsService {
            service_type: ty.into(),
            instance: instance.into(),
            host: String::new(),
            port: 0,
            txt: BTreeMap::new(),
        }
    }

    #[test]
    fn prefers_naming_services_over_hostname() {
        let mut d = device();
        assert_eq!(name(&d).as_deref(), Some("host-9"));
        d.mdns_services
            .push(svc("_http._tcp.local.", "generic web"));
        assert_eq!(name(&d).as_deref(), Some("host-9"));
        d.mdns_services
            .push(svc("_raop._tcp.local.", "A1B2C3D4E5F6@Kitchen"));
        assert_eq!(name(&d).as_deref(), Some("Kitchen"));
    }

    #[test]
    fn a_self_reported_name_wins() {
        let mut d = device();
        d.mdns_services
            .push(svc("_raop._tcp.local.", "A1B2C3D4E5F6@Kitchen"));
        d.info.push(crate::inventory::DeviceInfo {
            protocol: "amazon",
            from: String::new(),
            name: Some("Kitchen Echo Show".into()),
            product: None,
            model: None,
            firmware: None,
            mac: None,
            details: Vec::new(),
        });
        assert_eq!(name(&d).as_deref(), Some("Kitchen Echo Show"));
    }

    #[test]
    fn services_are_deduplicated_and_plumbing_is_hidden() {
        let mut d = device();
        for ty in [
            "_airplay._tcp.local.",
            "_raop._tcp.local.",
            "_companion-link._tcp.local.",
            "_ipp._tcp.local.",
        ] {
            d.mdns_services.push(svc(ty, "x"));
        }
        assert_eq!(services(&d), vec!["AirPlay", "Printer"]);
    }

    #[test]
    fn urls_prefer_resolvable_names() {
        use crate::inventory::NameSource;
        let mut d = device();
        assert_eq!(url(&d, 80), "http://10.0.0.9/");
        assert_eq!(url(&d, 8443), "https://10.0.0.9:8443/");
        assert_eq!(url(&d, 22), "ssh://10.0.0.9/");
        d.names.insert(NameSource::Mdns, "Office-Printer".into());
        assert_eq!(url(&d, 631), "http://Office-Printer.local:631/");
        d.names.insert(NameSource::Dns, "printer.lan.".into());
        assert_eq!(url(&d, 443), "https://printer.lan/");
        d.names.insert(NameSource::Dns, "PRINTER".into());
        assert_eq!(url(&d, 443), "https://Office-Printer.local/");
    }
}
