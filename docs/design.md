# eggprobe design

[Back to the README](../README.md)

## Principles

1. **Live, partial, honest results.** Findings appear as they arrive; `s`
   stops and keeps them, `r` rescans. Stale data is labelled as stale, unknowns
   say "unknown", and every classification cites its evidence.
2. **Least privilege and no footprint.** No root, no raw sockets, no config
   files, no services, nothing written between runs.
3. **One control scheme.** Arrows and j/k, the mouse, `/` to filter, `?` for
   help, `q` to quit.
4. **Headless mode.** `--scan` prints JSON with defined exit codes
   (0 / 1 / 2 / 130), so scans can be scripted.

## Architecture

```
src/main.rs            CLI and exit codes
src/netif.rs           interface, subnet and gateway selection
src/scan.rs            runs the sources in order and feeds the inventory
src/inventory.rs       the device table, and linking tailnet peers to devices
src/sources/           tailscale, neighbors, tcp (sweep and port probe),
                       names (reverse DNS, NetBIOS, unicast mDNS), mdns,
                       device_info (self-descriptions over HTTP and TXT),
                       tuya (passive broadcast listener);
                       wire.rs holds the DNS and NetBIOS packet code,
                       http.rs a minimal HTTP/1.1 GET
src/classify.rs        rules → kind, product, confidence and cited reasons
src/oui.rs             the embedded IEEE vendor table (see data/)
src/report.rs          the JSON report for --scan
src/ui/                the ratatui interface
```

Sources never touch the inventory. They send `Event`s over a channel and a
single coordinator applies them. The interface draws from a brief snapshot
copied out under the inventory's lock about ten times a second.

## Scanning order and pacing

Sources run one at a time, never concurrently:

1. **tailscale**: a local query, no network traffic.
   **tuya** starts listening now and stops at the end: it only receives
   broadcasts, so it adds no traffic to pace.
2. **neighbors**: whatever the ARP table already holds.
3. **tcp-sweep**: connects to a few common ports on every address.
4. **neighbors** again: the sweep fills the ARP table, so this finds hosts
   that answer ARP but drop every TCP connection.
5. **names** and **port-probe**, on the hosts found so far, then
   **tailnet-probe**: the same ports on online tailnet peers that are not
   on the LAN (not shared-in nodes). This goes over Tailscale, usually
   through a relay, so it needs no ARP pacing, only longer timeouts.
6. **mdns**.
7. **device-info**, after a 3 s pause for mDNS's aftermath (below), on the
   devices identified so far.

**A TCP connect sweep needs pacing.** Starting connections to every address
at once floods the network with ARP requests, and most first attempts time
out. The sweep starts one host every 4 ms with a 1.5 s timeout. Port probes
wait 2 s after the sweep for ARP retries to settle, then open at most 8
connections per host.

**mDNS goes last because it can disrupt unicast traffic.** On some Wi-Fi
networks, TCP connections from every process on the machine mostly time out
while an mDNS browser is running and for several seconds afterwards. The
cause is not yet understood. Running mDNS last keeps it away from the TCP
stages; within the mDNS stage, the service-type meta-query is sent first and
known types are browsed only after 1.5 s.

## Classification

Every rule that matches adds a weighted signal with a plain-language reason.
Signals for the same kind reinforce each other; the strongest kind wins, and
a close runner-up is reported as the alternative. What a device says about
itself (mDNS service types, model identifiers, the OS Tailscale reports)
outweighs what is inferred (vendor, open ports, hostname patterns).

HTTP status codes are never evidence. A device answering 401 to a URL only
proves it has a login page; a classifier that trusts status codes labels
every router with a web UI as whatever that URL belongs to. The content of a
reply can be: WLED's `/json/info` counts only when it says `"brand": "WLED"`,
and then it is the strongest evidence there is.

## Self-descriptions

`device-info` asks a device for its own description only when another
source already points at the API (an mDNS service, a telling name plus the
open port, or a product's usual port), never by trying paths on every web
server. When a probe is chosen by port alone, only the reply decides.
Requests are plain-HTTP `GET`s with a 2 s deadline and a 64 KiB cap, at most
8 at a time, with one retry on timeout. HTTP is hand-rolled (`http.rs`) to keep TLS and a
client library out of the static builds; devices that describe themselves
serve plain HTTP on the LAN anyway.

TXT records that carry a description (ESPHome, Home Assistant, Google Cast,
Fire TV, commissionable Matter) are decoded as the `mdns` source reads them,
so they cost no extra traffic.

## Ideas for later

- More self-descriptions: Shelly (`/shelly`, `/rpc/Shelly.GetDeviceInfo`),
  Hue (`/api/config`), Roku (`:8060/query/device-info`), Sonos
  (`:1400/xml/device_description.xml`).
- Tuya devices on newer firmware (protocol 3.5) that don't broadcast on
  6666/6667.
- Asking each host for its services with a unicast DNS-SD query, which
  might replace much of the multicast browsing. Some ESP32 responders
  answer such queries with ID 0, so replies must be matched by address.
- UPnP/SSDP friendly names, for plugs and cameras that give no other name.
- HTTP page titles as classification evidence.
- A services view: each service type, with the devices offering it.
- Monitoring: rescanning on an interval and marking devices that come and go.
  Scans need a cool-down after mDNS (see above) before the next TCP sweep.
- Optionally remembering known devices, to highlight new ones.
- Understanding why mDNS results vary between runs, and the root cause of
  the disruption described above.
