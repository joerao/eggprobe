//! What devices say about themselves. Some devices serve a description of
//! themselves over plain HTTP with no login (WLED's `/json/info`); others put
//! one in their mDNS TXT records (ESPHome, Home Assistant, Google Cast).
//!
//! The HTTP half runs last, on devices other sources already point at: a
//! WLED advertisement or `wled-` name, or a port a known product listens on
//! (Plex 32400, Jellyfin 8096). Only GET is ever sent, only to paths that
//! describe the device without changing it, redirects are not followed and
//! no credentials are sent. A reply counts only when its content confirms
//! what it is (`"brand": "WLED"`); a status code alone proves nothing.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::Duration;

use ipnet::Ipv4Net;
use serde_json::Value;
use tokio::task::JoinSet;

use super::http;
use super::{Cancel, Sink, cancelled};
use crate::inventory::{Detail, Device, DeviceInfo, FindingKind, MdnsService, SourceState};

const TIMEOUT: Duration = Duration::from_secs(2);
/// ESP8266 and ESP32 web servers handle a few connections at a time, and
/// several may share one weak Wi-Fi link.
const CONCURRENCY: usize = 8;

/// Which product's self-description to ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Probe {
    Wled,
    Plex,
    /// Jellyfin, and Emby, which it forked from.
    Jellyfin,
}

/// A device to ask, on which port, for what.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub ip: Ipv4Addr,
    pub port: u16,
    pub probe: Probe,
}

/// Devices whose own API is worth asking: WLED by advertisement or by name
/// (mDNS misses some WLEDs on every run), and media servers by advertisement
/// or by their usual port.
pub fn targets<'a>(devices: impl IntoIterator<Item = &'a Device>) -> Vec<Target> {
    let mut out = Vec::new();
    for d in devices.into_iter().filter(|d| !d.is_self) {
        let advertised = |types: &[&str]| {
            d.mdns_services
                .iter()
                .find(|s| types.contains(&s.service_type.as_str()))
                .map(|s| s.port)
                .filter(|p| *p != 0)
        };
        let open = |p: u16| d.open_ports.contains(&p).then_some(p);
        let mut add = |port: Option<u16>, probe| {
            if let Some(port) = port {
                out.push(Target {
                    ip: d.ip,
                    port,
                    probe,
                });
            }
        };
        let named_wled = d.names.values().any(|n| n.to_lowercase().contains("wled"));
        add(
            advertised(&["_wled._tcp.local."]).or(open(80).filter(|_| named_wled)),
            Probe::Wled,
        );
        add(
            advertised(&["_plex._tcp.local.", "_plexmediasvr._tcp.local."]).or(open(32400)),
            Probe::Plex,
        );
        add(
            advertised(&["_jellyfin._tcp.local.", "_emby._tcp.local."]).or(open(8096)),
            Probe::Jellyfin,
        );
    }
    out
}

pub async fn run(sink: &Sink, targets: Vec<Target>, subnet: Ipv4Net, cancel: &mut Cancel) {
    if targets.is_empty() {
        sink.status(SourceState::Done("no devices with a known API".into()));
        return;
    }
    let mut queued: BTreeSet<(Ipv4Addr, Probe)> = targets.iter().map(|t| (t.ip, t.probe)).collect();
    let mut pending = targets;
    pending.reverse();
    let mut total = pending.len();
    let (mut done, mut answered, mut via_peers) = (0usize, 0usize, 0usize);
    let mut failures: Vec<String> = Vec::new();
    // Guessed by port and turned out to be something else: expected, so
    // only counted.
    let mut other = 0usize;
    let mut tasks = JoinSet::new();
    sink.status(SourceState::Running(format!("asking {total} services")));
    loop {
        while tasks.len() < CONCURRENCY
            && let Some(t) = pending.pop()
        {
            tasks.spawn(async move { (t, ask(t).await) });
        }
        let joined = tokio::select! {
            j = tasks.join_next() => j,
            _ = cancelled(cancel) => {
                tasks.abort_all();
                sink.status(SourceState::Stopped);
                return;
            }
        };
        let Some(joined) = joined else { break };
        let Ok((t, result)) = joined else { continue };
        done += 1;
        match result {
            Ok((info, peers)) => {
                answered += 1;
                sink.found(
                    t.ip,
                    FindingKind::Responded(format!("answered HTTP on :{}", t.port)),
                );
                sink.found(t.ip, FindingKind::Info(info));
                // WLEDs hear each other's UDP broadcasts; ask the ones mDNS
                // and every other source missed.
                for ip in peers {
                    if subnet.contains(&ip) && queued.insert((ip, Probe::Wled)) {
                        via_peers += 1;
                        total += 1;
                        pending.push(Target {
                            ip,
                            port: 80,
                            probe: Probe::Wled,
                        });
                    }
                }
            }
            Err(Miss::Other) => other += 1,
            Err(Miss::Failed(e)) => failures.push(format!("{}:{} {e}", t.ip, t.port)),
        }
        sink.progress(done, total);
    }
    let mut summary = format!("{answered} of {total} services described themselves");
    if via_peers > 0 {
        summary.push_str(&format!("; {via_peers} found through WLED peers"));
    }
    if other > 0 {
        summary.push_str(&format!("; {other} were something else"));
    }
    if !failures.is_empty() {
        summary.push_str(&format!("; no answer from {}", failures.join(", ")));
    }
    sink.status(SourceState::Done(summary));
}

/// Why a target gave no description.
enum Miss {
    /// It answered, but as something else.
    Other,
    /// No usable answer: refused, timed out, or an error status.
    Failed(String),
}

/// Asks `t` for its description, and for the peers it knows (WLED only).
async fn ask(t: Target) -> Result<(DeviceInfo, Vec<Ipv4Addr>), Miss> {
    let path = match t.probe {
        Probe::Wled => "/json/info",
        Probe::Plex => "/identity",
        Probe::Jellyfin => "/System/Info/Public",
    };
    let url = match t.port {
        80 => format!("http://{}{path}", t.ip),
        p => format!("http://{}:{p}{path}", t.ip),
    };
    let reply = match get(t, path).await {
        Ok(r) => r,
        // Not HTTP at all: a different service on the port.
        Err(http::Error::Malformed) => return Err(Miss::Other),
        Err(e) => return Err(Miss::Failed(e.to_string())),
    };
    // A description is a 200 whose body names the product.
    if reply.status != 200 {
        return Err(Miss::Failed(format!("HTTP {}", reply.status)));
    }
    let info = match t.probe {
        Probe::Wled => parse_wled(&reply.body, url),
        Probe::Plex => parse_plex(&reply.body, url),
        Probe::Jellyfin => parse_jellyfin(&reply.body, url),
    }
    .ok_or(Miss::Other)?;
    let peers = if t.probe == Probe::Wled {
        match get(t, "/json/nodes").await {
            Ok(r) if r.status == 200 => parse_wled_nodes(&r.body),
            _ => Vec::new(),
        }
    } else {
        Vec::new()
    };
    Ok((info, peers))
}

/// A timeout gets one retry: the first request to a sleeping ESP often
/// stalls.
async fn get(t: Target, path: &str) -> Result<http::Response, http::Error> {
    let reply = http::get(t.ip, t.port, path, TIMEOUT).await;
    if reply == Err(http::Error::Timeout) {
        return http::get(t.ip, t.port, path, TIMEOUT).await;
    }
    reply
}

fn blank(protocol: &'static str, from: String) -> DeviceInfo {
    DeviceInfo {
        protocol,
        from,
        name: None,
        product: None,
        model: None,
        firmware: None,
        mac: None,
        details: Vec::new(),
    }
}

fn detail(i: &mut DeviceInfo, label: &'static str, value: Option<String>) {
    if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
        i.details.push(Detail { label, value });
    }
}

// Media and camera servers are software on a host, not the host itself, so
// their server names go in the details and never replace the device's name.

/// Plex's `/identity`: JSON when asked for it, as we do, and a
/// one-element XML document otherwise.
pub fn parse_plex(body: &[u8], from: String) -> Option<DeviceInfo> {
    let (version, claimed) = match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            let mc = &v["MediaContainer"];
            mc["machineIdentifier"].as_str()?;
            (
                mc["version"].as_str().map(String::from),
                mc["claimed"].as_bool(),
            )
        }
        Err(_) => {
            let xml = std::str::from_utf8(body).ok()?;
            let start = xml.find("<MediaContainer")?;
            let tag = &xml[start..start + xml[start..].find('>')?];
            let attr = |name: &str| {
                let at = tag.find(&format!(" {name}=\""))? + name.len() + 3;
                Some(tag[at..at + tag[at..].find('"')?].to_string())
            };
            attr("machineIdentifier")?;
            (attr("version"), attr("claimed").map(|c| c == "1"))
        }
    };
    let mut i = blank("plex", from);
    i.product = Some("Plex Media Server".into());
    i.firmware = version;
    detail(
        &mut i,
        "Claimed",
        claimed.map(|c| {
            if c {
                "yes, signed in to a Plex account"
            } else {
                "no"
            }
            .into()
        }),
    );
    Some(i)
}

/// Jellyfin's (and Emby's) `/System/Info/Public`.
pub fn parse_jellyfin(body: &[u8], from: String) -> Option<DeviceInfo> {
    let v: Value = serde_json::from_slice(body).ok()?;
    let product = v["ProductName"].as_str()?.trim();
    let protocol = if product.to_lowercase().contains("jellyfin") {
        "jellyfin"
    } else if product.to_lowercase().contains("emby") {
        "emby"
    } else {
        return None;
    };
    let text = |key: &str| v[key].as_str().map(str::to_string);
    let mut i = blank(protocol, from);
    i.product = Some(product.to_string());
    i.firmware = text("Version");
    detail(&mut i, "Server name", text("ServerName"));
    detail(&mut i, "OS", text("OperatingSystem"));
    detail(&mut i, "Address", text("LocalAddress"));
    Some(i)
}

/// WLED's `/json/info`, or None unless it says it is WLED.
pub fn parse_wled(body: &[u8], from: String) -> Option<DeviceInfo> {
    let v: Value = serde_json::from_slice(body).ok()?;
    if !v["brand"].as_str()?.eq_ignore_ascii_case("wled") {
        return None;
    }
    fn s(v: &Value) -> Option<&str> {
        v.as_str().map(str::trim).filter(|s| !s.is_empty())
    }
    let n = |v: &Value| v.as_u64();
    let mut details = Vec::new();
    let mut add = |label, value: Option<String>| {
        if let Some(value) = value {
            details.push(Detail { label, value });
        }
    };
    let leds = &v["leds"];
    add(
        "LEDs",
        n(&leds["count"]).map(|c| match n(&leds["fps"]) {
            Some(fps) if fps > 0 => format!("{c} at {fps} fps"),
            _ => c.to_string(),
        }),
    );
    add(
        "Power",
        n(&leds["pwr"])
            .filter(|p| *p > 0)
            .map(|p| match n(&leds["maxpwr"]) {
                Some(max) if max > 0 => format!("{p} mA (limit {max} mA)"),
                _ => format!("{p} mA"),
            }),
    );
    add(
        "Effects",
        n(&v["fxcount"]).map(|fx| match n(&v["palcount"]) {
            Some(pal) => format!("{fx} effects, {pal} palettes"),
            None => format!("{fx} effects"),
        }),
    );
    if v["live"].as_bool() == Some(true) {
        add("Live", Some("receiving realtime data".into()));
    }
    let wifi = &v["wifi"];
    let mut signal = Vec::new();
    if let Some(pct) = n(&wifi["signal"]) {
        signal.push(format!("{pct}%"));
    }
    if let Some(rssi) = wifi["rssi"].as_i64() {
        signal.push(format!("{rssi} dBm"));
    }
    if let Some(ch) = n(&wifi["channel"]) {
        signal.push(format!("channel {ch}"));
    }
    add("Wi-Fi", (!signal.is_empty()).then(|| signal.join(" · ")));
    add("Wi-Fi AP", s(&wifi["bssid"]).map(String::from));
    add("Uptime", n(&v["uptime"]).map(uptime));
    add(
        "Free heap",
        n(&v["freeheap"]).map(|b| format!("{} KiB", b / 1024)),
    );
    add("Build", s(&v["release"]).map(String::from));
    add(
        "Peers",
        n(&v["ndc"])
            .filter(|c| *c > 0)
            .map(|c| format!("{c} other WLED{}", if c == 1 { "" } else { "s" })),
    );

    let arch = s(&v["arch"]);
    let chip = s(&v["e32model"]);
    Some(DeviceInfo {
        protocol: "wled",
        from,
        name: s(&v["name"])
            .filter(|n| !n.eq_ignore_ascii_case("wled"))
            .map(String::from),
        product: Some(match s(&v["product"]) {
            Some(p) if !p.eq_ignore_ascii_case("foss") => format!("WLED {p}"),
            _ => "WLED".into(),
        }),
        model: match (arch, chip) {
            (_, Some(chip)) => Some(chip.to_string()),
            (Some(arch), None) => Some(arch.to_uppercase()),
            _ => None,
        },
        firmware: s(&v["ver"]).map(|ver| match n(&v["vid"]) {
            Some(vid) => format!("{ver} (build {vid})"),
            None => ver.to_string(),
        }),
        mac: s(&v["mac"]).and_then(colon_mac),
        details,
    })
}

/// The other WLEDs a WLED has heard from, by address.
pub fn parse_wled_nodes(body: &[u8]) -> Vec<Ipv4Addr> {
    let Ok(v) = serde_json::from_slice::<Value>(body) else {
        return Vec::new();
    };
    v["nodes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| node["ip"].as_str()?.parse().ok())
        .collect()
}

/// A description in a service's TXT records, for the services that carry one.
pub fn from_txt(svc: &MdnsService) -> Option<DeviceInfo> {
    let txt = |key: &str| {
        svc.txt
            .get(key)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
            .map(String::from)
    };
    let ty = svc.service_type.trim_end_matches('.');
    let ty = ty.strip_suffix(".local").unwrap_or(ty);
    let blank = |protocol| blank(protocol, format!("mDNS {ty}"));
    let info = match ty {
        "_esphomelib._tcp" => {
            let mut i = blank("esphome");
            i.name = txt("friendly_name");
            i.product = Some(match txt("project_name") {
                Some(p) => p.replace('.', " "),
                None => "ESPHome".into(),
            });
            i.model = txt("board").or(txt("platform"));
            i.firmware = txt("version").map(|v| format!("ESPHome {v}"));
            i.mac = txt("mac").and_then(|m| colon_mac(&m));
            if let Some(v) = txt("project_version") {
                i.details.push(Detail {
                    label: "Project",
                    value: v,
                });
            }
            if let Some(n) = txt("network") {
                i.details.push(Detail {
                    label: "Network",
                    value: n,
                });
            }
            i
        }
        "_home-assistant._tcp" => {
            let mut i = blank("home-assistant");
            i.name = txt("location_name");
            i.product = Some("Home Assistant".into());
            i.firmware = txt("version");
            if let Some(url) = txt("internal_url").or(txt("base_url")) {
                i.details.push(Detail {
                    label: "URL",
                    value: url,
                });
            }
            i
        }
        "_googlecast._tcp" => {
            let mut i = blank("cast");
            i.name = txt("fn");
            i.model = txt("md");
            i
        }
        "_amzn-wplay._tcp" => {
            let mut i = blank("amazon");
            i.name = txt("n");
            i
        }
        "_matterc._udp" => {
            let mut i = blank("matter");
            i.name = txt("DN");
            i.model = txt("VP").and_then(|vp| {
                let (vendor, product) = vp.split_once('+').unwrap_or((&vp, ""));
                let vendor = vendor.parse::<u16>().ok()?;
                Some(match product.parse::<u16>() {
                    Ok(p) => format!("vendor 0x{vendor:04X}, product 0x{p:04X}"),
                    Err(_) => format!("vendor 0x{vendor:04X}"),
                })
            });
            i
        }
        _ => return None,
    };
    let empty = info.name.is_none()
        && info.product.is_none()
        && info.model.is_none()
        && info.firmware.is_none()
        && info.details.is_empty();
    (!empty).then_some(info)
}

/// `a0b1c2d3e4f5` → `A0:B1:C2:D3:E4:F5`, the form the neighbor table uses.
fn colon_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let pairs: Vec<String> = hex
        .to_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    Some(pairs.join(":"))
}

/// Seconds as `3d 4h 5m`.
fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    let mut parts = Vec::new();
    if d > 0 {
        parts.push(format!("{d}d"));
    }
    if h > 0 {
        parts.push(format!("{h}h"));
    }
    if m > 0 || parts.is_empty() {
        parts.push(format!("{m}m"));
    }
    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::SystemTime;

    const INFO: &[u8] = include_bytes!("testdata/wled_info.json");
    const NODES: &[u8] = include_bytes!("testdata/wled_nodes.json");

    fn detail<'a>(i: &'a DeviceInfo, label: &str) -> Option<&'a str> {
        i.details
            .iter()
            .find(|d| d.label == label)
            .map(|d| d.value.as_str())
    }

    #[test]
    fn wled_info() {
        let i = parse_wled(INFO, "http://x/json/info".into()).unwrap();
        assert_eq!(i.protocol, "wled");
        assert_eq!(i.name.as_deref(), Some("Shelf Lights"));
        assert_eq!(i.product.as_deref(), Some("WLED"));
        assert_eq!(i.model.as_deref(), Some("Example Chip"));
        assert_eq!(i.firmware.as_deref(), Some("0.1.0 (build 2400000)"));
        assert_eq!(i.mac.as_deref(), Some("A0:B1:C2:D3:E4:F5"));
        assert_eq!(detail(&i, "LEDs"), Some("60 at 42 fps"));
        assert_eq!(detail(&i, "Power"), Some("310 mA (limit 850 mA)"));
        assert_eq!(detail(&i, "Wi-Fi"), Some("76% · -62 dBm · channel 6"));
        assert_eq!(detail(&i, "Wi-Fi AP"), Some("02:00:00:00:00:01"));
        assert_eq!(detail(&i, "Uptime"), Some("1d 1h 1m"));
        assert_eq!(detail(&i, "Peers"), Some("2 other WLEDs"));
        assert_eq!(detail(&i, "Live"), None);
    }

    #[test]
    fn default_names_and_other_brands() {
        let mut v: Value = serde_json::from_slice(INFO).unwrap();
        v["name"] = "WLED".into();
        v["product"] = "Custom".into();
        let i = parse_wled(&serde_json::to_vec(&v).unwrap(), String::new()).unwrap();
        assert_eq!(i.name, None);
        assert_eq!(i.product.as_deref(), Some("WLED Custom"));
        v["brand"] = "Tasmota".into();
        assert_eq!(
            parse_wled(&serde_json::to_vec(&v).unwrap(), String::new()),
            None
        );
        assert_eq!(parse_wled(b"<html>login</html>", String::new()), None);
        assert_eq!(parse_wled(b"{}", String::new()), None);
    }

    #[test]
    fn wled_nodes() {
        assert_eq!(
            parse_wled_nodes(NODES),
            vec![Ipv4Addr::new(10, 0, 0, 32), Ipv4Addr::new(172, 16, 5, 9)]
        );
        assert!(parse_wled_nodes(b"nope").is_empty());
    }

    fn svc(ty: &str, port: u16, txt: &[(&str, &str)]) -> MdnsService {
        MdnsService {
            service_type: ty.into(),
            instance: "x".into(),
            host: String::new(),
            port,
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn txt_descriptions() {
        let tv = from_txt(&svc(
            "_amzn-wplay._tcp.local.",
            0,
            &[("n", "Kitchen Echo Show"), ("ad", "EXAMPLE")],
        ))
        .unwrap();
        assert_eq!(tv.name.as_deref(), Some("Kitchen Echo Show"));
        let esp = from_txt(&svc(
            "_esphomelib._tcp.local.",
            6053,
            &[
                ("friendly_name", "Garage Door"),
                ("version", "2024.6.1"),
                ("platform", "ESP32"),
                ("board", "example-board"),
                ("mac", "a4cf12aabbcc"),
            ],
        ))
        .unwrap();
        assert_eq!(esp.model.as_deref(), Some("example-board"));
        assert_eq!(esp.firmware.as_deref(), Some("ESPHome 2024.6.1"));
        assert_eq!(esp.mac.as_deref(), Some("A4:CF:12:AA:BB:CC"));
        let matter = from_txt(&svc(
            "_matterc._udp.local.",
            5540,
            &[("VP", "4874+77"), ("DN", "Desk Lamp")],
        ))
        .unwrap();
        assert_eq!(
            matter.model.as_deref(),
            Some("vendor 0x130A, product 0x004D")
        );
        // A WLED's TXT holds only its MAC, and an operational Matter record
        // only a flag: nothing to describe.
        assert_eq!(
            from_txt(&svc("_wled._tcp.local.", 80, &[("mac", "x")])),
            None
        );
        assert_eq!(
            from_txt(&svc("_matter._tcp.local.", 0, &[("T", "2")])),
            None
        );
        assert_eq!(
            from_txt(&svc("_amzn-wplay._tcp.local.", 0, &[("n", " ")])),
            None
        );
    }

    #[test]
    fn media_and_camera_servers() {
        for body in [
            &include_bytes!("testdata/plex_identity.json")[..],
            &include_bytes!("testdata/plex_identity.xml")[..],
        ] {
            let plex = parse_plex(body, String::new()).unwrap();
            assert_eq!(plex.product.as_deref(), Some("Plex Media Server"));
            assert_eq!(plex.firmware.as_deref(), Some("1.2.3.4567-abcdef012"));
            assert_eq!(
                detail(&plex, "Claimed"),
                Some("yes, signed in to a Plex account")
            );
            assert_eq!(plex.name, None);
        }
        assert_eq!(
            parse_plex(b"<html><title>Plex</title></html>", String::new()),
            None
        );

        let jf =
            parse_jellyfin(include_bytes!("testdata/jellyfin_info.json"), String::new()).unwrap();
        assert_eq!(jf.protocol, "jellyfin");
        assert_eq!(jf.firmware.as_deref(), Some("10.0.0"));
        assert_eq!(detail(&jf, "Server name"), Some("Media"));
        assert_eq!(detail(&jf, "OS"), None);
        assert_eq!(jf.name, None);
        assert_eq!(
            parse_jellyfin(br#"{"ProductName":"Other"}"#, String::new()),
            None
        );
    }

    fn device(ip: u8, names: &[&str], ports: &[u16], wled_port: Option<u16>) -> Device {
        Device {
            ip: Ipv4Addr::new(10, 0, 0, ip),
            mac: None,
            hostname: None,
            names: names
                .iter()
                .map(|n| (crate::inventory::NameSource::Dns, n.to_string()))
                .collect(),
            workgroup: None,
            responding: true,
            is_self: false,
            is_gateway: false,
            open_ports: ports.iter().copied().collect::<BTreeSet<_>>(),
            mdns_services: wled_port
                .map(|p| vec![svc("_wled._tcp.local.", p, &[])])
                .unwrap_or_default(),
            info: Vec::new(),
            evidence: BTreeSet::new(),
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }

    fn t(ip: u8, port: u16, probe: Probe) -> Target {
        Target {
            ip: Ipv4Addr::new(10, 0, 0, ip),
            port,
            probe,
        }
    }

    #[test]
    fn targets_by_advertisement_or_name() {
        let devices: BTreeMap<_, _> = [
            device(2, &[], &[], Some(8080)),
            device(3, &["wled-shelf"], &[80], None),
            device(4, &["wled-quiet"], &[], None),
            device(5, &["printer"], &[80], None),
            device(6, &["mediapc"], &[80, 8096, 32400], None),
        ]
        .into_iter()
        .map(|d| (d.ip, d))
        .collect();
        assert_eq!(
            targets(devices.values()),
            vec![
                t(2, 8080, Probe::Wled),
                t(3, 80, Probe::Wled),
                t(6, 32400, Probe::Plex),
                t(6, 8096, Probe::Jellyfin),
            ]
        );
    }

    #[test]
    fn uptimes() {
        assert_eq!(uptime(0), "0m");
        assert_eq!(uptime(3600), "1h");
        assert_eq!(uptime(200_000), "2d 7h 33m");
    }
}
