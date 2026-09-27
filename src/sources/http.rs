//! Just enough HTTP/1.1 to read a device's own description of itself: one
//! plain-HTTP GET, no redirects, no TLS, a size cap and a deadline. Devices
//! that describe themselves (WLED, Shelly, Hue) serve small JSON bodies on
//! port 80, so anything larger or slower is not what we are looking for.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bodies larger than this are abandoned; WLED's `/json/info` is about 2 KiB.
pub const MAX_BODY: usize = 64 * 1024;
const MAX_HEAD: usize = 8 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Timeout,
    Connect(String),
    /// The reply was not HTTP, or was cut short.
    Malformed,
    TooLarge,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Timeout => write!(f, "timed out"),
            Error::Connect(e) => write!(f, "{e}"),
            Error::Malformed => write!(f, "not a valid HTTP reply"),
            Error::TooLarge => write!(f, "reply too large"),
        }
    }
}

/// GETs `path` from `ip:port`, finishing within `deadline`.
pub async fn get(
    ip: Ipv4Addr,
    port: u16,
    path: &str,
    deadline: Duration,
) -> Result<Response, Error> {
    tokio::time::timeout(deadline, fetch(ip, port, path))
        .await
        .unwrap_or(Err(Error::Timeout))
}

async fn fetch(ip: Ipv4Addr, port: u16, path: &str) -> Result<Response, Error> {
    let mut stream = TcpStream::connect(SocketAddr::from((ip, port)))
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;
    let host = if port == 80 {
        ip.to_string()
    } else {
        format!("{ip}:{port}")
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: eggprobe/{}\r\n\
         Accept: application/json, */*\r\nConnection: close\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| Error::Connect(e.to_string()))?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        // Embedded servers often ignore `Connection: close`, so stop as soon
        // as the body is complete rather than waiting for the socket to close.
        if let Some(done) = parse(&buf, false)? {
            return Ok(done);
        }
        let n = stream.read(&mut chunk).await.unwrap_or(0);
        if n == 0 {
            return parse(&buf, true)?.ok_or(Error::Malformed);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > MAX_HEAD + MAX_BODY {
            return Err(Error::TooLarge);
        }
    }
}

/// A complete response from `buf`, None if more bytes are needed. `eof`
/// means the server closed the connection, which ends a body that has no
/// length.
fn parse(buf: &[u8], eof: bool) -> Result<Option<Response>, Error> {
    let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if eof || buf.len() > MAX_HEAD {
            Err(Error::Malformed)
        } else {
            Ok(None)
        };
    };
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| Error::Malformed)?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .filter(|l| l.starts_with("HTTP/1."))
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or(Error::Malformed)?;
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = Some(value.parse::<usize>().map_err(|_| Error::Malformed)?);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value.to_ascii_lowercase().contains("chunked");
        }
    }
    let rest = &buf[head_end + 4..];
    let body = if chunked {
        match dechunk(rest)? {
            Some(body) => body,
            None if eof => return Err(Error::Malformed),
            None => return Ok(None),
        }
    } else if let Some(len) = length {
        if len > MAX_BODY {
            return Err(Error::TooLarge);
        }
        match rest.get(..len) {
            Some(body) => body.to_vec(),
            None if eof => return Err(Error::Malformed),
            None => return Ok(None),
        }
    } else if eof {
        rest.to_vec()
    } else {
        return Ok(None);
    };
    if body.len() > MAX_BODY {
        return Err(Error::TooLarge);
    }
    Ok(Some(Response { status, body }))
}

/// The body of a chunked transfer, None until the final chunk has arrived.
fn dechunk(mut rest: &[u8]) -> Result<Option<Vec<u8>>, Error> {
    let mut body = Vec::new();
    loop {
        let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") else {
            return Ok(None);
        };
        let size = std::str::from_utf8(&rest[..eol]).map_err(|_| Error::Malformed)?;
        let size = size.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| Error::Malformed)?;
        if size == 0 {
            return Ok(Some(body));
        }
        if body.len() + size > MAX_BODY {
            return Err(Error::TooLarge);
        }
        let start = eol + 2;
        let Some(data) = rest.get(start..start + size) else {
            return Ok(None);
        };
        body.extend_from_slice(data);
        match rest.get(start + size..start + size + 2) {
            Some(b"\r\n") => rest = &rest[start + size + 2..],
            Some(_) => return Err(Error::Malformed),
            None => return Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(body: &str) -> Option<Response> {
        Some(Response {
            status: 200,
            body: body.as_bytes().to_vec(),
        })
    }

    #[test]
    fn content_length_ends_the_body_without_eof() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse(r, false), Ok(ok("hello")));
        assert_eq!(parse(&r[..r.len() - 1], false), Ok(None));
        assert_eq!(parse(&r[..r.len() - 1], true), Err(Error::Malformed));
    }

    #[test]
    fn chunked_bodies_are_joined() {
        let r = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n4\r\n{\"a\"\r\n3;x=y\r\n:1}\r\n0\r\n\r\n";
        assert_eq!(parse(r, false), Ok(ok("{\"a\":1}")));
        assert_eq!(parse(&r[..r.len() - 5], false), Ok(None));
    }

    #[test]
    fn no_length_reads_to_eof() {
        let r = b"HTTP/1.0 404 Not Found\r\nServer: x\r\n\r\nnope";
        assert_eq!(parse(r, false), Ok(None));
        assert_eq!(
            parse(r, true),
            Ok(Some(Response {
                status: 404,
                body: b"nope".to_vec()
            }))
        );
    }

    #[test]
    fn garbage_and_oversize_are_rejected() {
        assert_eq!(
            parse(b"SSH-2.0-OpenSSH\r\n\r\n", false),
            Err(Error::Malformed)
        );
        assert_eq!(parse(b"SSH-2.0-OpenSSH", true), Err(Error::Malformed));
        let big = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert_eq!(parse(big.as_bytes(), false), Err(Error::TooLarge));
        assert_eq!(
            parse(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
                false
            ),
            Err(Error::Malformed)
        );
    }

    #[tokio::test]
    async fn round_trip_against_a_local_server() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut req = vec![0u8; 1024];
            let n = s.read(&mut req).await.unwrap();
            let req = String::from_utf8_lossy(&req[..n]).to_string();
            assert!(req.starts_with("GET /json/info HTTP/1.1\r\n"), "{req}");
            assert!(
                req.contains(&format!("Host: 127.0.0.1:{port}\r\n")),
                "{req}"
            );
            // Keep the socket open: the client must stop on Content-Length.
            s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let r = get(
            Ipv4Addr::LOCALHOST,
            port,
            "/json/info",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(r, Ok(ok("{}").unwrap()));
    }
}
