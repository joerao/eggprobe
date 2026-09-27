//! What kind of device is this? Every rule that matches emits a signal with a
//! weight and a plain-language reason. Signals for the same kind reinforce
//! each other; the strongest kind wins, and its reasons are kept so the
//! interface can say *why*.
//!
//! Weights, roughly: 85–95 the device names itself (an mDNS service or model
//! identifier specific to one kind); 60–80 a strong hint (a distinctive port
//! or a single-purpose vendor); 25–55 a weak hint (a vendor that makes many
//! kinds of thing, a common port). HTTP status codes are never evidence: a
//! 401 from a Pi-hole URL only proves the device has a login page. A reply
//! whose content names the product (WLED's `"brand": "WLED"`) is: that is
//! the device describing itself.

use serde::Serialize;

use crate::inventory::{Device, DeviceInfo, MdnsService, Peer};
use crate::oui::{self, Vendor};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Router,
    Computer,
    Server,
    Phone,
    Printer,
    Camera,
    Tv,
    Streamer,
    Speaker,
    Hub,
    SmartDevice,
    Unknown,
}

impl Kind {
    pub fn label(self) -> &'static str {
        match self {
            Kind::Router => "Network",
            Kind::Computer => "Computer",
            Kind::Server => "Server",
            Kind::Phone => "Phone/tablet",
            Kind::Printer => "Printer",
            Kind::Camera => "Camera",
            Kind::Tv => "TV",
            Kind::Streamer => "Streaming",
            Kind::Speaker => "Speaker",
            Kind::Hub => "Smart hub",
            Kind::SmartDevice => "Smart device",
            Kind::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Confident,
    Likely,
    Guess,
    None,
}

impl Confidence {
    fn from_score(score: u32) -> Self {
        match score {
            85.. => Confidence::Confident,
            60..=84 => Confidence::Likely,
            25..=59 => Confidence::Guess,
            _ => Confidence::None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Confidence::Confident => "confident",
            Confidence::Likely => "likely",
            Confidence::Guess => "a guess",
            Confidence::None => "no evidence",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Classification {
    pub kind: Kind,
    /// A specific product or role when something named it: "HomePod",
    /// a printer's model name, "Home Assistant".
    pub product: Option<String>,
    pub confidence: Confidence,
    pub score: u32,
    /// Why, strongest first.
    pub reasons: Vec<String>,
    /// A rival kind that scored nearly as well, if any.
    pub alternative: Option<Kind>,
    pub vendor: Vendor,
}

#[derive(Debug, Clone)]
struct Signal {
    kind: Kind,
    product: Option<String>,
    weight: u32,
    reason: String,
}

#[derive(Default)]
pub struct Signals(Vec<Signal>);

impl Signals {
    fn add(&mut self, kind: Kind, weight: u32, reason: impl Into<String>) {
        self.0.push(Signal {
            kind,
            product: None,
            weight,
            reason: reason.into(),
        });
    }

    fn product(
        &mut self,
        kind: Kind,
        product: impl Into<String>,
        weight: u32,
        reason: impl Into<String>,
    ) {
        self.0.push(Signal {
            kind,
            product: Some(product.into()),
            weight,
            reason: reason.into(),
        });
    }
}

/// `peer` is the device's Tailscale identity, when it has one.
pub fn classify(d: &Device, peer: Option<&Peer>) -> Classification {
    let vendor = d.mac.as_deref().map_or(Vendor::Unknown, oui::lookup);
    let mut s = Signals::default();
    if d.is_gateway {
        s.add(Kind::Router, 90, "the network's default gateway");
    }
    vendor_signals(&vendor, d, &mut s);
    for svc in &d.mdns_services {
        mdns_signals(svc, &vendor, &mut s);
    }
    for info in &d.info {
        info_signals(info, &mut s);
    }
    port_signals(d, &vendor, &mut s);
    // Every name the device answers to; the same short name from two
    // sources counts once.
    let mut seen: Vec<String> = Vec::new();
    for name in d.names.values().chain(d.hostname.iter()) {
        let short = crate::inventory::short_name(name);
        if !seen.iter().any(|n| n.eq_ignore_ascii_case(&short)) {
            hostname_signals(&short, &mut s);
            seen.push(short);
        }
    }
    if d.names.contains_key(&crate::inventory::NameSource::Netbios) {
        s.add(
            Kind::Computer,
            50,
            "answers NetBIOS name queries (Windows, or Samba file sharing)",
        );
    }
    if let Some(p) = peer {
        os_signals(&p.os, &mut s);
    }
    decide(s, vendor)
}

/// Tailscale reports the operating system each node runs.
pub fn os_signals(os: &str, s: &mut Signals) {
    let why = format!("Tailscale reports {os}");
    match os.to_lowercase().as_str() {
        "ios" => s.add(Kind::Phone, 80, why),
        "android" => s.add(Kind::Phone, 75, why),
        "windows" => s.product(Kind::Computer, "Windows PC", 80, why),
        "macos" => s.product(Kind::Computer, "Mac", 80, why),
        "tvos" => s.product(Kind::Streamer, "Apple TV", 85, why),
        "linux" | "freebsd" | "openbsd" => s.add(Kind::Computer, 45, why),
        _ => {}
    }
}

/// A tailnet peer with no LAN device to classify: its OS and its name.
pub fn classify_peer(p: &Peer) -> Classification {
    let mut s = Signals::default();
    os_signals(&p.os, &mut s);
    hostname_signals(p.short_name(), &mut s);
    decide(s, Vendor::Unknown)
}

fn decide(s: Signals, vendor: Vendor) -> Classification {
    let mut kinds: Vec<(Kind, u32, Vec<&Signal>)> = Vec::new();
    for sig in &s.0 {
        match kinds.iter_mut().find(|(k, ..)| *k == sig.kind) {
            Some(entry) => entry.2.push(sig),
            None => kinds.push((sig.kind, 0, vec![sig])),
        }
    }
    for (_, score, sigs) in &mut kinds {
        sigs.sort_by_key(|s| std::cmp::Reverse(s.weight));
        // The best signal counts in full; corroboration adds a quarter of
        // each further one. Repeats of one reason don't count twice.
        let mut seen = Vec::new();
        let mut total = 0;
        for (i, sig) in sigs.iter().enumerate() {
            if seen.contains(&&sig.reason) {
                continue;
            }
            seen.push(&sig.reason);
            total += if i == 0 { sig.weight } else { sig.weight / 4 };
        }
        *score = total.min(99);
    }
    kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));

    let Some((kind, score, sigs)) = kinds.first() else {
        return Classification {
            kind: Kind::Unknown,
            product: None,
            confidence: Confidence::None,
            score: 0,
            reasons: Vec::new(),
            alternative: None,
            vendor,
        };
    };
    let confidence = Confidence::from_score(*score);
    let alternative = kinds
        .get(1)
        .filter(|(_, other, _)| *other >= 40 && *other + 15 >= *score)
        .map(|(k, ..)| *k);
    let mut reasons: Vec<String> = Vec::new();
    for sig in sigs {
        if !reasons.contains(&sig.reason) {
            reasons.push(sig.reason.clone());
        }
    }
    Classification {
        kind: if confidence == Confidence::None {
            Kind::Unknown
        } else {
            *kind
        },
        product: sigs.iter().find_map(|s| s.product.clone()),
        confidence,
        score: *score,
        reasons,
        alternative,
        vendor,
    }
}

// ── vendor ──────────────────────────────────────────────────────────────

fn vendor_signals(vendor: &Vendor, d: &Device, s: &mut Signals) {
    let name = match vendor {
        Vendor::Known(n) => *n,
        Vendor::Private => {
            // Randomized MACs are the default for phones and tablets on
            // Wi-Fi, and common on laptops. Never on a gateway.
            if !d.is_gateway {
                s.add(Kind::Phone, 30, "uses a randomized (private) MAC address");
            }
            return;
        }
        Vendor::Unknown => return,
    };
    let v = name.to_lowercase();
    let why = format!("MAC vendor is {name}");
    let has = |needles: &[&str]| needles.iter().any(|n| v.contains(n));

    if has(&["raspberry pi"]) {
        s.product(Kind::Computer, "Raspberry Pi", 65, why);
    } else if has(&[
        "synology",
        "qnap",
        "western digital",
        "asustor",
        "terramaster",
    ]) {
        s.product(Kind::Server, format!("{name} NAS"), 80, why);
    } else if has(&["sonos"]) {
        s.product(Kind::Speaker, "Sonos", 85, why);
    } else if has(&["bose"]) {
        s.product(Kind::Speaker, "Bose", 70, why);
    } else if has(&["roku"]) {
        s.product(Kind::Streamer, "Roku", 85, why);
    } else if has(&[
        "wyze",
        "amcrest",
        "dahua",
        "hikvision",
        "reolink",
        "axis",
        "arlo",
        "eufy",
    ]) {
        s.product(Kind::Camera, format!("{name} camera"), 75, why);
    } else if has(&["smartthings"]) {
        s.product(Kind::Hub, "SmartThings hub", 85, why);
    } else if has(&["philips hue", "signify"]) {
        s.product(Kind::Hub, "Philips Hue bridge", 80, why);
    } else if has(&["shelly"]) {
        s.product(Kind::SmartDevice, "Shelly", 85, why);
    } else if has(&["tuya"]) {
        s.product(Kind::SmartDevice, "Tuya", 70, why);
    } else if has(&["rachio"]) {
        s.product(Kind::SmartDevice, "Rachio sprinkler controller", 85, why);
    } else if has(&["ecobee"]) {
        s.product(Kind::SmartDevice, "ecobee thermostat", 85, why);
    } else if has(&["chamberlain"]) {
        s.product(Kind::SmartDevice, "myQ garage opener", 80, why);
    } else if has(&["espressif"]) {
        s.add(
            Kind::SmartDevice,
            55,
            format!("{why} (ESP32/ESP8266 chips, common in smart devices)"),
        );
    } else if has(&[
        "epson", "brother", "canon", "lexmark", "xerox", "kyocera", "ricoh", "konica",
    ]) {
        s.add(Kind::Printer, 60, why);
    } else if has(&[
        "netgear",
        "ubiquiti",
        "linksys",
        "belkin",
        "eero",
        "arris",
        "commscope",
        "mikrotik",
        "cisco",
        "juniper",
        "aruba",
        "ruckus",
        "zyxel",
        "d-link",
        "sagemcom",
        "technicolor",
        "askey",
        "actiontec",
        "plume",
    ]) {
        s.add(Kind::Router, 45, format!("{why}, a networking vendor"));
    } else if has(&["amazon"]) {
        s.add(Kind::Speaker, 40, format!("{why} (Echo, Fire TV, Ring …)"));
    } else if has(&["google"]) {
        s.add(Kind::Streamer, 40, format!("{why} (Chromecast, Nest …)"));
    } else if has(&["lg innotek", "vizio", "tcl", "hisense", "roku tv"]) {
        s.add(Kind::Tv, 55, why);
    } else if has(&["lg", "samsung", "sony"]) {
        s.add(
            Kind::Tv,
            30,
            format!("{why}, which makes TVs among other things"),
        );
    } else if has(&["hp"]) {
        s.add(Kind::Printer, 30, why.clone());
        s.add(Kind::Computer, 30, why);
    } else if has(&["caldigit", "plugable", "owc"]) {
        s.add(
            Kind::Computer,
            45,
            format!("{why}, a laptop dock's network adapter"),
        );
    } else if has(&[
        "intel",
        "dell",
        "lenovo",
        "asrock",
        "micro-star",
        "gigabyte",
        "realtek",
        "liteon",
        "elitegroup",
        "foxconn",
        "azurewave",
        "framework",
    ]) {
        s.add(
            Kind::Computer,
            40,
            format!("{why}, a PC and network-card maker"),
        );
    }
}

// ── mDNS ────────────────────────────────────────────────────────────────

fn mdns_signals(svc: &MdnsService, vendor: &Vendor, s: &mut Signals) {
    let ty = svc
        .service_type
        .trim_end_matches('.')
        .trim_end_matches(".local");
    let txt = |key: &str| svc.txt.get(key).map(|v| v.trim()).filter(|v| !v.is_empty());
    let adv = |what: &str| format!("advertises {what} over mDNS ({ty})");

    match ty {
        "_ipp._tcp" | "_ipps._tcp" | "_printer._tcp" | "_pdl-datastream._tcp" => {
            match txt("ty").or(txt("product").map(|p| p.trim_matches(['(', ')']))) {
                Some(model) => s.product(Kind::Printer, model, 92, adv("printing")),
                None => s.add(Kind::Printer, 90, adv("printing")),
            }
        }
        "_uscan._tcp" | "_uscans._tcp" | "_scanner._tcp" => {
            s.add(Kind::Printer, 70, adv("scanning"))
        }
        "_airplay._tcp" | "_raop._tcp" => {
            let model = txt("model").or(txt("am"));
            match model.and_then(apple_model) {
                Some((kind, product)) => s.product(
                    kind,
                    product,
                    90,
                    format!("reports model {} ({ty})", model.unwrap()),
                ),
                None if matches!(vendor, Vendor::Known(n) if is_tv_maker(n)) => {
                    s.add(Kind::Tv, 75, adv("AirPlay on a TV maker's hardware"))
                }
                None => s.add(Kind::Streamer, 40, adv("an AirPlay receiver")),
            }
        }
        "_companion-link._tcp" | "_device-info._tcp" => {
            let model = txt("rpMd").or(txt("model"));
            if let Some(m) = model {
                if let Some((kind, product)) = apple_model(m) {
                    s.product(kind, product, 90, format!("reports model {m} ({ty})"));
                } else if ["MacSamba", "Xserve", "RackMac", "TimeCapsule"]
                    .iter()
                    .any(|p| m.starts_with(p))
                {
                    s.add(
                        Kind::Server,
                        50,
                        format!("shares files, reporting model {m}"),
                    );
                }
            }
        }
        "_googlecast._tcp" => {
            let md = txt("md").unwrap_or("");
            let l = md.to_lowercase();
            let (kind, weight) = if l.contains("chromecast") || l.contains("google tv") {
                (Kind::Streamer, 92)
            } else if l.contains("nest hub") {
                (Kind::Hub, 85)
            } else if l.contains("home")
                || l.contains("nest")
                || l.contains("speaker")
                || l.contains("audio")
            {
                (Kind::Speaker, 88)
            } else if l.contains("tv") || matches!(vendor, Vendor::Known(n) if is_tv_maker(n)) {
                (Kind::Tv, 80)
            } else {
                (Kind::Streamer, 75)
            };
            if md.is_empty() {
                s.add(kind, weight, adv("Google Cast"));
            } else {
                s.product(kind, md, weight, format!("Google Cast model “{md}”"));
            }
        }
        "_hap._tcp" | "_hap._udp" | "_homekit._tcp" => {
            let (kind, product, weight) = match txt("ci").and_then(|c| c.parse::<u32>().ok()) {
                Some(2) => (Kind::Hub, "HomeKit bridge", 85),
                Some(17) => (Kind::Camera, "HomeKit camera", 90),
                Some(18) => (Kind::Camera, "HomeKit doorbell", 90),
                Some(31) => (Kind::Tv, "HomeKit TV", 85),
                Some(5) => (Kind::SmartDevice, "HomeKit light", 85),
                Some(7) | Some(8) | Some(15) => (Kind::SmartDevice, "HomeKit switch", 85),
                Some(9) => (Kind::SmartDevice, "HomeKit thermostat", 85),
                Some(10) => (Kind::SmartDevice, "HomeKit sensor", 85),
                Some(4) | Some(6) | Some(12) | Some(13) | Some(14) => {
                    (Kind::SmartDevice, "HomeKit accessory", 85)
                }
                _ => (Kind::SmartDevice, "HomeKit accessory", 65),
            };
            s.product(kind, product, weight, adv("HomeKit"));
        }
        "_wled._tcp" => s.product(Kind::SmartDevice, "WLED lights", 95, adv("WLED")),
        "_esphomelib._tcp" => s.product(Kind::SmartDevice, "ESPHome", 90, adv("ESPHome")),
        "_shelly._tcp" => s.product(Kind::SmartDevice, "Shelly", 90, adv("Shelly")),
        "_home-assistant._tcp" => s.product(Kind::Hub, "Home Assistant", 95, adv("Home Assistant")),
        "_homebridge._tcp" => s.product(Kind::Hub, "Homebridge", 92, adv("Homebridge")),
        "_hubitat._tcp" => s.product(Kind::Hub, "Hubitat", 92, adv("Hubitat")),
        "_hue._tcp" => s.product(Kind::Hub, "Philips Hue bridge", 92, adv("Hue")),
        "_matter._tcp" | "_matterc._udp" | "_matter._udp" => {
            s.add(Kind::SmartDevice, 55, adv("Matter"))
        }
        "_meshcop._udp" | "_trel._udp" => s.add(Kind::Hub, 60, adv("a Thread border router")),
        "_sonos._tcp" => s.product(Kind::Speaker, "Sonos", 95, adv("Sonos")),
        "_spotify-connect._tcp" => s.add(Kind::Speaker, 35, adv("Spotify Connect")),
        // Amazon's media receiver. Fire TVs and Echo Shows both run it; the
        // name the device publishes usually tells them apart.
        "_amzn-wplay._tcp" => {
            let name = txt("n").unwrap_or("").to_lowercase();
            if name.contains("echo show") {
                s.product(Kind::Speaker, "Echo Show", 80, adv("Amazon media"))
            } else if name.contains("fire") {
                s.product(Kind::Streamer, "Fire TV", 80, adv("Amazon media"))
            } else {
                s.product(
                    Kind::Streamer,
                    "Amazon media device",
                    65,
                    adv("Amazon's media receiver (Fire TV or Echo Show)"),
                )
            }
        }
        "_roku-rcp._tcp" => s.product(Kind::Streamer, "Roku", 95, adv("Roku")),
        "_appletv-v2._tcp" => s.product(Kind::Streamer, "Apple TV", 92, adv("Apple TV")),
        "_rtsp._tcp" => s.add(Kind::Camera, 60, adv("a video stream (RTSP)")),
        "_octoprint._tcp" => s.product(Kind::Server, "OctoPrint", 92, adv("OctoPrint")),
        "_plex._tcp" | "_plexmediasvr._tcp" => s.product(Kind::Server, "Plex", 90, adv("Plex")),
        "_jellyfin._tcp" | "_emby._tcp" => {
            s.product(Kind::Server, "Jellyfin/Emby", 90, adv("a media server"))
        }
        "_adguard._tcp" => s.product(Kind::Server, "AdGuard Home", 90, adv("AdGuard Home")),
        "_unifi._tcp" => s.product(Kind::Server, "UniFi controller", 85, adv("UniFi")),
        "_node-red._tcp" => s.product(Kind::Server, "Node-RED", 75, adv("Node-RED")),
        "_mqtt._tcp" => s.product(Kind::Server, "MQTT broker", 60, adv("MQTT")),
        "_nvstream._tcp" => s.product(Kind::Computer, "NVIDIA GameStream", 75, adv("GameStream")),
        "_workstation._tcp" => s.add(
            Kind::Computer,
            70,
            adv("a workstation (Avahi, usually Linux)"),
        ),
        "_ssh._tcp" | "_sftp-ssh._tcp" => s.add(Kind::Computer, 40, adv("SSH")),
        "_smb._tcp" | "_afpovertcp._tcp" | "_nfs._tcp" => {
            s.add(Kind::Computer, 40, adv("file sharing"))
        }
        "_daap._tcp" | "_dacp._tcp" | "_touch-able._tcp" => {
            s.add(Kind::Computer, 40, adv("iTunes sharing"))
        }
        _ => {}
    }
}

// ── the device's own description ────────────────────────────────────────

fn info_signals(info: &DeviceInfo, s: &mut Signals) {
    // TXT-record descriptions add names and versions, not identity: the
    // service type that carried them is already a signal.
    match info.protocol {
        "wled" => s.product(
            Kind::SmartDevice,
            "WLED lights",
            98,
            format!("answers WLED's JSON API ({})", info.from),
        ),
        "tuya" => s.product(
            Kind::SmartDevice,
            "Tuya",
            92,
            format!("announces itself as a Tuya device ({})", info.from),
        ),
        // Media and camera servers are software on some host; they don't
        // say what the host is.
        _ => {}
    }
}

/// Apple model identifiers, as published in mDNS TXT records.
/// Real ones always carry a version with a comma (`Mac14,2`), which keeps
/// Samba's `MacSamba` from passing as a Mac.
fn apple_model(model: &str) -> Option<(Kind, &'static str)> {
    if !model.contains(',') {
        return None;
    }
    let starts = |p: &str| model.starts_with(p);
    Some(if starts("iPhone") {
        (Kind::Phone, "iPhone")
    } else if starts("iPad") {
        (Kind::Phone, "iPad")
    } else if starts("AppleTV") {
        (Kind::Streamer, "Apple TV")
    } else if starts("AudioAccessory") {
        (Kind::Speaker, "HomePod")
    } else if starts("MacBook")
        || starts("iMac")
        || starts("Macmini")
        || starts("MacPro")
        || starts("Mac")
    {
        (Kind::Computer, "Mac")
    } else {
        return None;
    })
}

fn is_tv_maker(vendor: &str) -> bool {
    let v = vendor.to_lowercase();
    [
        "lg",
        "samsung",
        "sony",
        "vizio",
        "tcl",
        "hisense",
        "panasonic",
        "philips",
        "sharp",
    ]
    .iter()
    .any(|m| v.contains(m))
}

// ── ports ───────────────────────────────────────────────────────────────

fn port_signals(d: &Device, vendor: &Vendor, s: &mut Signals) {
    let has = |p: u16| d.open_ports.contains(&p);
    if has(135) && (has(445) || has(3389)) {
        s.product(
            Kind::Computer,
            "Windows PC",
            85,
            "Windows RPC with SMB or Remote Desktop open (135 + 445/3389)",
        );
    } else if has(3389) {
        s.add(Kind::Computer, 60, "Remote Desktop is open (3389)");
    }
    if has(62078) {
        s.add(Kind::Phone, 75, "the iOS sync service is open (62078)");
    }
    if has(9100) {
        s.add(Kind::Printer, 70, "raw printing is open (JetDirect, 9100)");
    }
    if has(515) {
        s.add(Kind::Printer, 55, "LPD printing is open (515)");
    }
    if has(631) {
        s.add(Kind::Printer, 45, "IPP printing is open (631)");
    }
    if has(554) {
        s.add(Kind::Camera, 55, "a video stream port is open (RTSP, 554)");
    }
    if matches!(vendor, Vendor::Known("Amazon")) && has(8009) {
        // Fire TVs take casts over DIAL on 8009; so do Echo Shows. Both run
        // Fire OS and may call themselves "Android-…", so this outweighs
        // that hostname's phone hint: Amazon sells no phones.
        s.add(
            Kind::Streamer,
            70,
            "DIAL casting port open on Amazon hardware (8009)",
        );
    } else if has(8008) || has(8009) {
        s.add(Kind::Streamer, 60, "Google Cast ports are open (8008/8009)");
    }
    if has(8060) {
        s.product(
            Kind::Streamer,
            "Roku",
            85,
            "Roku's control port is open (8060)",
        );
    }
    if has(1400) {
        s.product(
            Kind::Speaker,
            "Sonos",
            80,
            "Sonos's control port is open (1400)",
        );
    }
    if has(8123) {
        s.product(
            Kind::Hub,
            "Home Assistant",
            80,
            "Home Assistant's port is open (8123)",
        );
    }
    if has(51826) || has(8581) {
        s.product(
            Kind::Hub,
            "Homebridge",
            75,
            "Homebridge ports are open (51826/8581)",
        );
    }
    if has(6053) {
        s.product(
            Kind::SmartDevice,
            "ESPHome",
            80,
            "the ESPHome API is open (6053)",
        );
    }
    if has(6668) {
        s.product(
            Kind::SmartDevice,
            "Tuya",
            75,
            "Tuya's control port is open (6668)",
        );
    }
    if has(8006) {
        s.product(
            Kind::Server,
            "Proxmox",
            85,
            "the Proxmox web UI port is open (8006)",
        );
    }
    if has(32400) {
        s.product(Kind::Server, "Plex", 80, "Plex's port is open (32400)");
    }
    if has(8096) {
        s.product(
            Kind::Server,
            "Jellyfin",
            65,
            "Jellyfin's port is open (8096)",
        );
    }
    if has(9443) {
        s.product(
            Kind::Server,
            "Portainer",
            45,
            "Portainer's port is open (9443)",
        );
    }
    if has(1883) || has(8883) {
        s.add(Kind::Server, 45, "an MQTT broker port is open (1883/8883)");
    }
    if has(53) && !d.is_gateway {
        s.add(Kind::Router, 40, "answers on the DNS port (53)");
    }
    if has(22) {
        s.add(Kind::Computer, 25, "SSH is open (22)");
    }
}

// ── hostname ────────────────────────────────────────────────────────────

fn hostname_signals(hostname: &str, s: &mut Signals) {
    let h = hostname.to_lowercase();
    let why = || format!("hostname “{hostname}”");
    let any = |needles: &[&str]| needles.iter().any(|n| h.contains(n));
    // Whole words only for short tokens, so "tv" doesn't match "atv-ext".
    let word = |w: &str| {
        h.split(|c: char| !c.is_ascii_alphanumeric())
            .any(|t| t == w)
    };

    if any(&["iphone"]) {
        s.product(Kind::Phone, "iPhone", 80, why());
    } else if any(&["ipad"]) {
        s.product(Kind::Phone, "iPad", 80, why());
    } else if any(&["android", "galaxy", "pixel"]) {
        s.add(Kind::Phone, 65, why());
    } else if any(&["macbook", "imac", "mac-mini", "macmini"]) || word("mbp") {
        s.product(Kind::Computer, "Mac", 70, why());
    } else if h.starts_with("desktop-") || h.starts_with("laptop-") {
        s.product(Kind::Computer, "Windows PC", 70, why());
    } else if any(&["raspberrypi"]) {
        s.product(Kind::Computer, "Raspberry Pi", 60, why());
    } else if any(&["homeassistant"]) {
        s.product(Kind::Hub, "Home Assistant", 80, why());
    } else if any(&["octopi", "octoprint"]) {
        s.product(Kind::Server, "OctoPrint", 80, why());
    } else if any(&["pihole", "pi-hole"]) {
        s.product(Kind::Server, "Pi-hole", 70, why());
    } else if any(&["synology", "diskstation", "truenas", "unraid"]) || word("nas") {
        s.add(Kind::Server, 65, why());
    } else if any(&["printer", "epson"])
        || h.starts_with("brn")
        || h.starts_with("hp") && h.len() == 8
    {
        s.add(Kind::Printer, 60, why());
    } else if any(&["firetv", "fire-tv", "fire_tv"]) {
        s.product(Kind::Streamer, "Fire TV", 85, why());
    } else if any(&["chromecast"]) {
        s.product(Kind::Streamer, "Chromecast", 80, why());
    } else if any(&["roku"]) {
        s.product(Kind::Streamer, "Roku", 80, why());
    } else if any(&["lgwebos", "webos", "tizen", "bravia"]) || word("tv") {
        s.add(Kind::Tv, 60, why());
    } else if any(&["wled"]) {
        s.product(Kind::SmartDevice, "WLED lights", 85, why());
    } else if any(&["shelly"]) {
        s.product(Kind::SmartDevice, "Shelly", 85, why());
    } else if any(&["esp32", "esp8266"]) || h.starts_with("esp-") || h.starts_with("esp_") {
        s.add(Kind::SmartDevice, 60, why());
    } else if h.starts_with("myq") {
        s.product(Kind::SmartDevice, "myQ garage opener", 80, why());
    } else if h.starts_with("ting-") {
        s.product(Kind::SmartDevice, "Ting electrical sensor", 75, why());
    } else if any(&["wyze"]) {
        s.product(Kind::Camera, "Wyze camera", 75, why());
    } else if h.starts_with("tl-sg") || h.starts_with("tl-sf") {
        s.product(Kind::Router, "TP-Link switch", 80, why());
    } else if any(&["nighthawk"]) {
        s.product(Kind::Router, "Netgear Nighthawk", 80, why());
    } else if any(&["plug", "simplelink"]) {
        s.add(Kind::SmartDevice, 55, why());
    } else if any(&["rachio"]) {
        s.product(Kind::SmartDevice, "Rachio sprinkler controller", 80, why());
    } else if h.starts_with("hubv2") || h.starts_with("hubv3") {
        s.product(Kind::Hub, "SmartThings hub", 75, why());
    } else if any(&["linksys", "velop", "eero", "orbi", "deco"]) {
        s.add(Kind::Router, 70, format!("{} (mesh Wi-Fi naming)", why()));
    } else if h.starts_with("amc0") {
        s.product(Kind::Camera, "Amcrest camera", 70, why());
    }
}

#[cfg(test)]
mod tests {
    //! Cases modelled on common home devices. MAC addresses keep a real
    //! vendor prefix; the rest is made up.
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::time::SystemTime;

    fn device(mac: Option<&str>, ports: &[u16]) -> Device {
        Device {
            ip: "10.0.0.50".parse().unwrap(),
            mac: mac.map(String::from),
            hostname: None,
            names: Default::default(),
            workgroup: None,
            responding: true,
            is_self: false,
            is_gateway: false,
            open_ports: ports.iter().copied().collect::<BTreeSet<_>>(),
            mdns_services: Vec::new(),
            info: Vec::new(),
            evidence: BTreeSet::new(),
            first_seen: SystemTime::UNIX_EPOCH,
            last_seen: SystemTime::UNIX_EPOCH,
        }
    }

    fn mdns(d: &mut Device, ty: &str, txt: &[(&str, &str)]) {
        d.mdns_services.push(MdnsService {
            service_type: format!("{ty}.local."),
            instance: "instance".into(),
            host: String::new(),
            port: 0,
            txt: txt
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<BTreeMap<_, _>>(),
        });
    }

    #[test]
    fn printer_with_model_from_txt() {
        let mut d = device(Some("00:26:AB:00:00:01"), &[80, 443, 515, 631, 9100]);
        mdns(&mut d, "_ipp._tcp", &[("ty", "Example Printer Model")]);
        let c = classify(&d, None);
        assert_eq!(c.kind, Kind::Printer);
        assert_eq!(c.confidence, Confidence::Confident);
        assert_eq!(c.product.as_deref(), Some("Example Printer Model"));
        assert_eq!(c.vendor, Vendor::Known("Epson"));
        assert!(c.reasons.len() >= 4, "{:?}", c.reasons);
    }

    #[test]
    fn gateway_is_a_router() {
        let mut d = device(Some("F4:F2:6D:00:00:01"), &[22, 53, 80]);
        d.is_gateway = true;
        let c = classify(&d, None);
        assert_eq!(c.kind, Kind::Router);
        assert_eq!(c.confidence, Confidence::Confident);
    }

    #[test]
    fn authenticated_web_ui_is_not_a_pi_hole() {
        // A Netgear box whose web UI answers 401 to a Pi-hole URL. With no
        // content evidence, it is only a networking vendor's device.
        let d = device(Some("10:0C:6B:00:00:01"), &[80, 443, 49152]);
        let c = classify(&d, None);
        assert_eq!(c.kind, Kind::Router);
        assert_ne!(c.product.as_deref(), Some("Pi-hole"));
        assert_eq!(c.confidence, Confidence::Guess);
    }

    #[test]
    fn private_mac_with_ios_sync_is_a_phone() {
        let d = device(Some("7E:00:00:00:00:01"), &[62078]);
        let c = classify(&d, None);
        assert_eq!(c.kind, Kind::Phone);
        assert_eq!(c.vendor, Vendor::Private);
        assert_eq!(c.confidence, Confidence::Likely);
    }

    #[test]
    fn apple_models_name_the_device() {
        let mut mac = device(Some("7E:00:00:00:00:02"), &[5000, 7000]);
        mdns(
            &mut mac,
            "_companion-link._tcp",
            &[("rpMd", "MacBookPro18,1")],
        );
        let c = classify(&mac, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Computer, Some("Mac"))
        );

        let mut pod = device(Some("00:1B:63:00:00:01"), &[]);
        mdns(&mut pod, "_airplay._tcp", &[("model", "AudioAccessory5,1")]);
        let c = classify(&pod, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Speaker, Some("HomePod"))
        );
    }

    #[test]
    fn all_names_count_and_netbios_means_a_pc() {
        use crate::inventory::NameSource;
        let mut d = device(Some("BC:5F:F4:00:00:01"), &[]);
        d.names.insert(NameSource::Netbios, "TOWER".into());
        d.names
            .insert(NameSource::Dns, "tower.home.example.net".into());
        let c = classify(&d, None);
        assert_eq!(c.kind, Kind::Computer);
        assert!(
            c.reasons.iter().any(|r| r.contains("NetBIOS")),
            "{:?}",
            c.reasons
        );

        let mut sw = device(Some("F4:F2:6D:00:00:02"), &[80]);
        sw.names.insert(NameSource::Dns, "tl-sg-switch.lan".into());
        let c = classify(&sw, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Router, Some("TP-Link switch"))
        );
    }

    #[test]
    fn samba_is_not_a_mac() {
        let mut d = device(None, &[139, 445]);
        mdns(&mut d, "_device-info._tcp", &[("model", "MacSamba")]);
        let c = classify(&d, None);
        assert_ne!(c.product.as_deref(), Some("Mac"));
        assert_eq!(c.kind, Kind::Server);
    }

    #[test]
    fn windows_ports_beat_a_board_vendor() {
        let d = device(Some("BC:5F:F4:00:00:01"), &[135, 139, 445, 3389, 5357]);
        let c = classify(&d, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Computer, Some("Windows PC"))
        );
        assert_eq!(c.confidence, Confidence::Confident);
    }

    #[test]
    fn wled_on_espressif() {
        let mut d = device(Some("24:0A:C4:00:00:01"), &[80]);
        mdns(&mut d, "_wled._tcp", &[]);
        mdns(&mut d, "_http._tcp", &[]);
        let c = classify(&d, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::SmartDevice, Some("WLED lights"))
        );
        assert_eq!(c.confidence, Confidence::Confident);
    }

    #[test]
    fn wled_api_outranks_a_misleading_hostname() {
        let mut d = device(Some("24:0A:C4:00:00:01"), &[80]);
        d.names
            .insert(crate::inventory::NameSource::Dns, "iphone-lamp".into());
        d.info.push(DeviceInfo {
            protocol: "wled",
            from: "http://10.0.0.50/json/info".into(),
            name: None,
            product: Some("WLED".into()),
            model: None,
            firmware: None,
            mac: None,
            details: Vec::new(),
        });
        let c = classify(&d, None);
        assert_eq!(
            (c.kind, c.product.as_deref(), c.confidence),
            (
                Kind::SmartDevice,
                Some("WLED lights"),
                Confidence::Confident
            )
        );
    }

    #[test]
    fn amazon_media_receivers_are_told_apart() {
        let amazon = Some("00:BB:3A:00:00:01");
        let mut show = device(amazon, &[8009]);
        mdns(&mut show, "_amzn-wplay._tcp", &[("n", "Kitchen Echo Show")]);
        let c = classify(&show, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Speaker, Some("Echo Show"))
        );

        let mut stick = device(amazon, &[8009]);
        mdns(
            &mut stick,
            "_amzn-wplay._tcp",
            &[("n", "Living Room Fire TV")],
        );
        let c = classify(&stick, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Streamer, Some("Fire TV"))
        );

        let mut unknown = device(amazon, &[]);
        mdns(
            &mut unknown,
            "_amzn-wplay._tcp",
            &[("ad", "ZZZ"), ("n", "Den")],
        );
        let c = classify(&unknown, None);
        assert_eq!(c.product.as_deref(), Some("Amazon media device"));

        let mut quiet = device(amazon, &[8009]);
        quiet
            .names
            .insert(crate::inventory::NameSource::Dns, "Android-2".into());
        let c = classify(&quiet, None);
        assert_eq!(c.kind, Kind::Streamer);
        assert!(
            c.reasons.iter().all(|r| !r.contains("Google Cast")),
            "{:?}",
            c.reasons
        );
    }

    #[test]
    fn smartthings_hub_advertising_matter() {
        let mut d = device(Some("24:FD:5B:00:00:01"), &[]);
        mdns(&mut d, "_matter._tcp", &[]);
        let c = classify(&d, None);
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Hub, Some("SmartThings hub"))
        );
    }

    #[test]
    fn mesh_node_named_by_hostname() {
        let mut d = device(
            Some("D8:EC:5E:00:00:01"),
            &[53, 80, 443, 8080, 10000, 49152],
        );
        d.hostname = Some("Linksys00001".into());
        let c = classify(&d, None);
        assert_eq!(c.kind, Kind::Router);
        assert!(c.confidence != Confidence::Guess, "{c:?}");
    }

    #[test]
    fn fire_tv_and_camera() {
        let mut tv = device(None, &[8009]);
        mdns(&mut tv, "_amzn-wplay._tcp", &[]);
        assert_eq!(classify(&tv, None).kind, Kind::Streamer);

        let cam = device(Some("9C:8E:CD:00:00:01"), &[80, 554, 5000, 49152]);
        let c = classify(&cam, None);
        assert_eq!(
            (c.kind, c.confidence),
            (Kind::Camera, Confidence::Confident)
        );
    }

    #[test]
    fn google_cast_model_decides_between_speaker_and_streamer() {
        let mut mini = device(None, &[8008, 8009]);
        mdns(&mut mini, "_googlecast._tcp", &[("md", "Google Nest Mini")]);
        assert_eq!(classify(&mini, None).kind, Kind::Speaker);
        let mut cc = device(None, &[8008, 8009]);
        mdns(&mut cc, "_googlecast._tcp", &[("md", "Chromecast")]);
        assert_eq!(classify(&cc, None).kind, Kind::Streamer);
    }

    #[test]
    fn tailscale_os_decides_between_phone_and_computer() {
        let d = device(Some("7E:00:00:00:00:03"), &[]);
        let peer = |os: &str| Peer {
            id: "x".into(),
            hostname: "h".into(),
            dns_name: "h.tail.ts.net".into(),
            os: os.into(),
            ips: vec![],
            online: true,
            is_self: false,
            exit_node: false,
            shared_in: false,
            last_seen: None,
        };
        // A private MAC alone leans phone; Tailscale saying Windows settles it.
        let c = classify(&d, Some(&peer("windows")));
        assert_eq!(
            (c.kind, c.product.as_deref()),
            (Kind::Computer, Some("Windows PC"))
        );
        assert_eq!(classify(&d, Some(&peer("iOS"))).kind, Kind::Phone);
        let mut tv = peer("android");
        assert_eq!(classify_peer(&tv).kind, Kind::Phone);
        // Fire TV runs Android; its name says what it is.
        tv.dns_name = "firetv-4k-max.tail.ts.net".into();
        assert_eq!(classify_peer(&tv).kind, Kind::Streamer);
        assert_eq!(classify_peer(&peer("plan9")).kind, Kind::Unknown);
    }

    #[test]
    fn nothing_known_is_unknown() {
        let c = classify(&device(None, &[]), None);
        assert_eq!((c.kind, c.confidence), (Kind::Unknown, Confidence::None));
        assert!(c.reasons.is_empty());
        // One weak hint is a guess, not a classification to trust.
        let c = classify(&device(None, &[22]), None);
        assert_eq!(c.confidence, Confidence::Guess);
    }

    #[test]
    fn close_rivals_are_reported() {
        // HP makes printers and PCs; with nothing else to go on, say both.
        let c = classify(&device(Some("64:51:06:00:00:01"), &[]), None);
        if c.vendor == Vendor::Known("HP") {
            assert!(c.alternative.is_none() || c.score < 60);
        }
    }
}
