//! Just enough of the DNS wire format for name lookups: PTR queries (to a DNS
//! server, or unicast to a device's mDNS responder) and NetBIOS node-status
//! queries, which share the same packet layout.

use std::net::Ipv4Addr;

pub const TYPE_PTR: u16 = 12;
const TYPE_NBSTAT: u16 = 0x21;
const CLASS_IN: u16 = 1;

/// A PTR query for `ip`'s reverse name. `recursive` asks a DNS server to
/// resolve it; mDNS responders expect it clear.
pub fn ptr_query(id: u16, ip: Ipv4Addr, recursive: bool) -> Vec<u8> {
    let [a, b, c, d] = ip.octets();
    let name = format!("{d}.{c}.{b}.{a}.in-addr.arpa");
    let mut p = header(id, if recursive { 0x0100 } else { 0 });
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&TYPE_PTR.to_be_bytes());
    p.extend_from_slice(&CLASS_IN.to_be_bytes());
    p
}

/// A NetBIOS node-status query for the wildcard name `*`, which every
/// NetBIOS host answers with the list of names it holds.
pub fn nbstat_query(id: u16) -> Vec<u8> {
    let mut p = header(id, 0);
    // "*" padded with NULs to 16 bytes, first-level encoded: each nibble + 'A'.
    let mut raw = [0u8; 16];
    raw[0] = b'*';
    p.push(32);
    for byte in raw {
        p.push(b'A' + (byte >> 4));
        p.push(b'A' + (byte & 0x0f));
    }
    p.push(0);
    p.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
    p.extend_from_slice(&CLASS_IN.to_be_bytes());
    p
}

fn header(id: u16, flags: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(64);
    for field in [id, flags, 1, 0, 0, 0] {
        p.extend_from_slice(&field.to_be_bytes());
    }
    p
}

/// The PTR targets in a response to query `id`, without the trailing dot.
pub fn ptr_answers(buf: &[u8], id: u16) -> Option<Vec<String>> {
    let mut r = Reader::new(buf);
    if r.u16()? != id {
        return None;
    }
    let _flags = r.u16()?;
    let (qd, an) = (r.u16()?, r.u16()?);
    r.skip(4)?;
    for _ in 0..qd {
        r.name()?;
        r.skip(4)?;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        r.name()?;
        let (ty, _class) = (r.u16()?, r.u16()?);
        r.skip(4)?;
        let len = r.u16()? as usize;
        let end = r.pos + len;
        if ty == TYPE_PTR {
            let name = r.name()?;
            if !name.is_empty() {
                out.push(name);
            }
        }
        r.pos = end;
    }
    Some(out)
}

#[derive(Debug, PartialEq, Eq)]
pub struct NetBios {
    /// The computer name: the unique name with suffix 0x00.
    pub name: String,
    /// The workgroup or domain: the group name with suffix 0x00.
    pub workgroup: Option<String>,
}

/// Parses a node-status response to query `id`.
pub fn nbstat_answer(buf: &[u8], id: u16) -> Option<NetBios> {
    let mut r = Reader::new(buf);
    if r.u16()? != id {
        return None;
    }
    r.skip(2)?;
    let (qd, an) = (r.u16()?, r.u16()?);
    r.skip(4)?;
    for _ in 0..qd {
        r.name()?;
        r.skip(4)?;
    }
    if an == 0 {
        return None;
    }
    r.name()?;
    r.skip(2 + 2 + 4 + 2)?; // type, class, ttl, rdlength
    let count = r.u8()?;
    let (mut name, mut workgroup) = (None, None);
    for _ in 0..count {
        let raw = r.bytes(15)?;
        let suffix = r.u8()?;
        let flags = r.u16()?;
        let text = String::from_utf8_lossy(raw).trim_end().to_string();
        let group = flags & 0x8000 != 0;
        if suffix == 0x00 && !text.is_empty() {
            if group {
                workgroup.get_or_insert(text);
            } else {
                name.get_or_insert(text);
            }
        }
    }
    Some(NetBios {
        name: name?,
        workgroup,
    })
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes([self.u8()?, self.u8()?]))
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        (self.pos + n <= self.buf.len()).then(|| self.pos += n)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let slice = self.buf.get(self.pos..self.pos + n)?;
        self.pos += n;
        Some(slice)
    }

    /// A possibly compressed domain name. Bounded, so a pointer loop in a
    /// hostile packet cannot hang the scan.
    fn name(&mut self) -> Option<String> {
        let mut labels = Vec::new();
        let mut pos = self.pos;
        let mut jumped = false;
        for _ in 0..128 {
            let len = *self.buf.get(pos)? as usize;
            if len == 0 {
                if !jumped {
                    self.pos = pos + 1;
                }
                return Some(labels.join("."));
            }
            if len & 0xc0 == 0xc0 {
                let target = ((len & 0x3f) << 8) | *self.buf.get(pos + 1)? as usize;
                if !jumped {
                    self.pos = pos + 2;
                }
                jumped = true;
                pos = target;
                continue;
            }
            let label = self.buf.get(pos + 1..pos + 1 + len)?;
            labels.push(String::from_utf8_lossy(label).into_owned());
            pos += 1 + len;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response echoing `query` with the given answer records appended.
    fn response(query: &[u8], answers: &[Vec<u8>]) -> Vec<u8> {
        let mut r = query.to_vec();
        r[2] |= 0x80; // QR
        r[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for a in answers {
            r.extend_from_slice(a);
        }
        r
    }

    fn ptr_record(target: &str) -> Vec<u8> {
        let mut rdata = Vec::new();
        for label in target.split('.') {
            rdata.push(label.len() as u8);
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        let mut rec = vec![0xc0, 12]; // pointer to the question name
        rec.extend_from_slice(&TYPE_PTR.to_be_bytes());
        rec.extend_from_slice(&CLASS_IN.to_be_bytes());
        rec.extend_from_slice(&60u32.to_be_bytes());
        rec.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rec.extend_from_slice(&rdata);
        rec
    }

    #[test]
    fn ptr_round_trip() {
        let q = ptr_query(0x1234, Ipv4Addr::new(10, 0, 0, 5), true);
        let reversed = b"\x015\x010\x010\x0210\x07in-addr";
        assert!(q.windows(reversed.len()).any(|w| w == reversed));
        let r = response(&q, &[ptr_record("tower.home.example.net")]);
        assert_eq!(
            ptr_answers(&r, 0x1234),
            Some(vec!["tower.home.example.net".into()])
        );
        assert_eq!(ptr_answers(&r, 0x9999), None, "wrong id");
        assert_eq!(ptr_answers(&response(&q, &[]), 0x1234), Some(vec![]));
        assert_eq!(ptr_answers(&r[..20], 0x1234), None, "truncated");
    }

    #[test]
    fn netbios_names_and_workgroup() {
        let q = nbstat_query(7);
        assert_eq!(&q[13..15], b"CK", "'*' encodes as CK");
        let entry = |name: &str, suffix: u8, group: bool| {
            let mut e = format!("{name:<15}").into_bytes();
            e.push(suffix);
            e.extend_from_slice(&(if group { 0x8400u16 } else { 0x0400 }).to_be_bytes());
            e
        };
        let mut rdata = vec![3];
        rdata.extend(entry("TOWER", 0x20, false));
        rdata.extend(entry("TOWER", 0x00, false));
        rdata.extend(entry("WORKGROUP", 0x00, true));
        let mut rec = vec![0xc0, 12];
        rec.extend_from_slice(&TYPE_NBSTAT.to_be_bytes());
        rec.extend_from_slice(&CLASS_IN.to_be_bytes());
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rec.extend_from_slice(&rdata);
        let r = response(&q, &[rec]);
        assert_eq!(
            nbstat_answer(&r, 7),
            Some(NetBios {
                name: "TOWER".into(),
                workgroup: Some("WORKGROUP".into())
            })
        );
    }

    #[test]
    fn compression_loops_are_rejected() {
        let mut r = ptr_query(1, Ipv4Addr::LOCALHOST, false);
        r[6..8].copy_from_slice(&1u16.to_be_bytes());
        let at = r.len() as u8;
        r.extend_from_slice(&[0xc0, at]); // a name that points at itself
        r.extend_from_slice(&[0, 12, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, at]);
        assert_eq!(ptr_answers(&r, 1), None);
    }
}
