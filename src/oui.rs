//! MAC vendor lookup from the IEEE registry, as packaged by Wireshark and
//! shortened by `scripts/update_oui.py`. The table is embedded, so the binary
//! stays self-contained; it is decompressed on first use (a few milliseconds).

use std::collections::HashMap;
use std::io::Read;
use std::sync::OnceLock;

use serde::Serialize;

static TABLE: &[u8] = include_bytes!("../data/oui.tsv.gz");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "name", rename_all = "lowercase")]
pub enum Vendor {
    Known(&'static str),
    /// Locally administered: randomized by the device (phones, laptops,
    /// tablets on Wi-Fi) or set by software (VMs, containers). No vendor.
    Private,
    Unknown,
}

impl Vendor {
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Vendor::Known(n) => Some(n),
            _ => None,
        }
    }
}

/// Keyed by the prefix's bit length and its value.
struct Db(HashMap<(u8, u64), &'static str>);

fn db() -> &'static Db {
    static DB: OnceLock<Db> = OnceLock::new();
    DB.get_or_init(|| {
        let mut text = String::new();
        flate2::read::GzDecoder::new(TABLE)
            .read_to_string(&mut text)
            .expect("embedded OUI table is valid gzip");
        // Lives for the whole process; leaking lets entries borrow from it.
        let text: &'static str = Box::leak(text.into_boxed_str());
        let mut map = HashMap::with_capacity(60_000);
        for line in text.lines() {
            let Some((hex, name)) = line.split_once('\t') else {
                continue;
            };
            let bits = (hex.len() * 4) as u8;
            if let Ok(value) = u64::from_str_radix(hex, 16) {
                map.insert((bits, value), name);
            }
        }
        Db(map)
    })
}

/// The vendor for a MAC written as `AA:BB:CC:DD:EE:FF`.
pub fn lookup(mac: &str) -> Vendor {
    let Some(value) = parse(mac) else {
        return Vendor::Unknown;
    };
    if (value >> 40) & 0x02 != 0 {
        return Vendor::Private;
    }
    // Most specific assignment first: /36 and /28 blocks sit inside /24s
    // registered to the IEEE itself.
    let db = db();
    for bits in [36u8, 28, 24] {
        if let Some(name) = db.0.get(&(bits, value >> (48 - bits))) {
            return Vendor::Known(name);
        }
    }
    Vendor::Unknown
}

fn parse(mac: &str) -> Option<u64> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    u64::from_str_radix(&hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors_use_display_names() {
        assert_eq!(lookup("00:26:AB:00:00:01"), Vendor::Known("Epson"));
        assert_eq!(lookup("F4:F2:6D:00:00:01"), Vendor::Known("TP-Link"));
        assert_eq!(lookup("B8:27:EB:00:00:01"), Vendor::Known("Raspberry Pi"));
        assert_eq!(lookup("00:1B:63:00:00:01"), Vendor::Known("Apple"));
    }

    #[test]
    fn randomized_addresses_are_private() {
        // Second-lowest bit of the first octet: 7E, A6, AE, CA, 42, C6 …
        for mac in [
            "7E:79:6E:00:00:01",
            "A6:AF:5D:00:00:01",
            "42:11:6A:00:00:01",
        ] {
            assert_eq!(lookup(mac), Vendor::Private, "{mac}");
        }
    }

    #[test]
    fn smaller_blocks_win_over_their_registry_prefix() {
        // 70:B3:D5 is the IEEE's own /24 (not listed itself), subdivided into
        // /36 assignments such as 70:B3:D5:00:1.
        assert!(matches!(lookup("70:B3:D5:00:10:00"), Vendor::Known(_)));
        assert_eq!(lookup("70:B3:D5:00:00:01"), Vendor::Unknown);
    }

    #[test]
    fn garbage_is_unknown() {
        assert_eq!(lookup("not a mac"), Vendor::Unknown);
    }
}
