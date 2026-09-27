//! Tuya devices (most no-name smart plugs, bulbs and switches) announce
//! themselves by UDP broadcast every few seconds: on port 6666 in plain JSON
//! (protocol 3.1), on 6667 encrypted (3.3 and later). The broadcast key is
//! the same on every device, so the announcements can be read by anyone
//! listening. They carry the device ID, protocol version and a product key
//! that identifies the model.
//!
//! This source only listens; it sends nothing, so it runs for the whole scan
//! alongside the others without adding traffic.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use aes::Aes128;
use aes::cipher::{BlockDecrypt, KeyInit, generic_array::GenericArray};
use serde_json::Value;
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use super::{Cancel, Sink, cancelled};
use crate::inventory::{Detail, DeviceInfo, FindingKind, SourceState};

/// MD5 of `yGAdlopoPVldABfn`, the broadcast key every Tuya device uses.
const KEY: [u8; 16] = [
    0x6c, 0x1e, 0xc8, 0xe2, 0xbb, 0x9b, 0xb5, 0x9a, 0xb5, 0x0b, 0x0d, 0xaf, 0x64, 0x9b, 0x41, 0x0a,
];
const PLAIN_PORT: u16 = 6666;
const ENCRYPTED_PORT: u16 = 6667;
const PREFIX: [u8; 4] = [0x00, 0x00, 0x55, 0xaa];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    pub id: String,
    pub product_key: Option<String>,
    pub version: Option<String>,
    pub port: u16,
}

/// Listens until `stop` fires or the scan is cancelled.
pub async fn run(sink: Sink, mut cancel: Cancel, mut stop: oneshot::Receiver<()>) {
    let plain = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, PLAIN_PORT)).await;
    let encrypted = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, ENCRYPTED_PORT)).await;
    let (plain, encrypted) = match (plain, encrypted) {
        (Err(e), Err(_)) => {
            // Usually another Tuya integration on this machine holds them.
            sink.status(SourceState::Unavailable(format!(
                "cannot listen on UDP {PLAIN_PORT}/{ENCRYPTED_PORT}: {e}"
            )));
            return;
        }
        (p, e) => (p.ok(), e.ok()),
    };
    sink.status(SourceState::Running("listening for broadcasts".into()));

    let mut heard: BTreeMap<Ipv4Addr, Announcement> = BTreeMap::new();
    let (mut buf_p, mut buf_e) = ([0u8; 1024], [0u8; 1024]);
    let stopped = loop {
        let (received, port) = tokio::select! {
            r = recv(plain.as_ref(), &mut buf_p) => (r, PLAIN_PORT),
            r = recv(encrypted.as_ref(), &mut buf_e) => (r, ENCRYPTED_PORT),
            _ = &mut stop => break false,
            _ = cancelled(&mut cancel) => break true,
        };
        let Some((len, IpAddr::V4(ip))) = received else {
            continue;
        };
        let buf = if port == PLAIN_PORT { &buf_p } else { &buf_e };
        let Some(a) = decode(&buf[..len], port) else {
            continue;
        };
        if heard.get(&ip) != Some(&a) {
            sink.found(
                ip,
                FindingKind::Responded("broadcasts Tuya discovery".into()),
            );
            sink.found(ip, FindingKind::Info(describe(&a, &[])));
            heard.insert(ip, a);
            sink.status(SourceState::Running(format!(
                "heard {} devices",
                heard.len()
            )));
        }
    };

    // Devices with the same product key are the same model: say which.
    for (ip, a) in &heard {
        let twins: Vec<Ipv4Addr> = heard
            .iter()
            .filter(|(other, b)| {
                *other != ip && a.product_key.is_some() && b.product_key == a.product_key
            })
            .map(|(other, _)| *other)
            .collect();
        if !twins.is_empty() {
            sink.found(*ip, FindingKind::Info(describe(a, &twins)));
        }
    }
    if stopped {
        sink.status(SourceState::Stopped);
        return;
    }
    let mut models: Vec<&str> = heard
        .values()
        .filter_map(|a| a.product_key.as_deref())
        .collect();
    models.sort_unstable();
    models.dedup();
    sink.status(SourceState::Done(format!(
        "{} devices announced themselves, {} distinct products",
        heard.len(),
        models.len()
    )));
}

async fn recv(socket: Option<&UdpSocket>, buf: &mut [u8]) -> Option<(usize, IpAddr)> {
    match socket {
        Some(s) => s.recv_from(buf).await.ok().map(|(n, from)| (n, from.ip())),
        None => std::future::pending().await,
    }
}

fn describe(a: &Announcement, twins: &[Ipv4Addr]) -> DeviceInfo {
    let mut details = vec![Detail {
        label: "Device ID",
        value: a.id.clone(),
    }];
    if !twins.is_empty() {
        let list: Vec<String> = twins.iter().map(|ip| ip.to_string()).collect();
        details.push(Detail {
            label: "Same model",
            value: list.join(", "),
        });
    }
    DeviceInfo {
        protocol: "tuya",
        from: format!("UDP {} broadcast", a.port),
        name: None,
        product: Some("Tuya device".into()),
        model: a.product_key.as_ref().map(|k| format!("product key {k}")),
        firmware: a.version.as_ref().map(|v| format!("Tuya protocol {v}")),
        mac: None,
        details,
    }
}

/// One broadcast frame: `00 00 55 AA`, sequence, command, length, return
/// code, payload, CRC, `00 00 AA 55`. The payload is JSON, encrypted with
/// AES-128-ECB on port 6667.
pub fn decode(packet: &[u8], port: u16) -> Option<Announcement> {
    let start = packet.windows(4).position(|w| w == PREFIX)?;
    let frame = &packet[start..];
    let len = u32::from_be_bytes(frame.get(12..16)?.try_into().ok()?) as usize;
    // `len` counts the return code, payload, CRC and suffix.
    let payload = frame.get(20..(16 + len).checked_sub(8)?)?;
    let json = if port == ENCRYPTED_PORT {
        decrypt(payload)?
    } else {
        payload.to_vec()
    };
    let v: Value = serde_json::from_slice(&json).ok()?;
    let text = |key: &str| {
        v[key]
            .as_str()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    Some(Announcement {
        id: text("gwId").or(text("devId"))?,
        product_key: text("productKey"),
        version: text("version"),
        port,
    })
}

fn decrypt(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(16) {
        return None;
    }
    let cipher = Aes128::new(GenericArray::from_slice(&KEY));
    let mut out = data.to_vec();
    for block in out.chunks_mut(16) {
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
    let pad = *out.last()? as usize;
    if pad == 0 || pad > 16 || out[out.len() - pad..].iter().any(|b| *b as usize != pad) {
        return None;
    }
    out.truncate(out.len() - pad);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::BlockEncrypt;

    const JSON: &str = r#"{"ip":"10.0.0.36","gwId":"eb0000000000000000abcd","active":2,"ability":0,"mode":0,"encrypt":true,"productKey":"keyabcdefghijklm","version":"3.3"}"#;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut f = PREFIX.to_vec();
        f.extend_from_slice(&0u32.to_be_bytes()); // sequence
        f.extend_from_slice(&0x13u32.to_be_bytes()); // command
        f.extend_from_slice(&((payload.len() + 12) as u32).to_be_bytes());
        f.extend_from_slice(&0u32.to_be_bytes()); // return code
        f.extend_from_slice(payload);
        f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // CRC, unchecked
        f.extend_from_slice(&[0x00, 0x00, 0xaa, 0x55]);
        f
    }

    fn encrypt(plain: &[u8]) -> Vec<u8> {
        let pad = 16 - plain.len() % 16;
        let mut data = plain.to_vec();
        data.extend(std::iter::repeat_n(pad as u8, pad));
        let cipher = Aes128::new(GenericArray::from_slice(&KEY));
        for block in data.chunks_mut(16) {
            cipher.encrypt_block(GenericArray::from_mut_slice(block));
        }
        data
    }

    #[test]
    fn encrypted_and_plain_announcements() {
        let want = Announcement {
            id: "eb0000000000000000abcd".into(),
            product_key: Some("keyabcdefghijklm".into()),
            version: Some("3.3".into()),
            port: ENCRYPTED_PORT,
        };
        assert_eq!(
            decode(&frame(&encrypt(JSON.as_bytes())), ENCRYPTED_PORT),
            Some(want.clone())
        );
        assert_eq!(
            decode(&frame(JSON.as_bytes()), PLAIN_PORT),
            Some(Announcement {
                port: PLAIN_PORT,
                ..want
            })
        );
    }

    #[test]
    fn junk_is_ignored() {
        assert_eq!(decode(b"hello", ENCRYPTED_PORT), None);
        // Plain JSON arriving on the encrypted port does not decrypt.
        assert_eq!(decode(&frame(JSON.as_bytes()), ENCRYPTED_PORT), None);
        let mut short = frame(&encrypt(JSON.as_bytes()));
        short.truncate(30);
        assert_eq!(decode(&short, ENCRYPTED_PORT), None);
        assert_eq!(decode(&frame(&encrypt(b"{\"x\":1}")), ENCRYPTED_PORT), None);
    }

    #[test]
    fn twins_are_listed() {
        let a = Announcement {
            id: "x".into(),
            product_key: Some("k".into()),
            version: None,
            port: ENCRYPTED_PORT,
        };
        let info = describe(&a, &[Ipv4Addr::new(10, 0, 0, 51)]);
        assert_eq!(info.model.as_deref(), Some("product key k"));
        assert_eq!(info.details[1].value, "10.0.0.51");
    }
}
