# eggprobe

Find and identify the devices on your network, from your terminal. No root needed.

> **Status: early.** Scanning, classification, Tailscale and the interactive
> view work; the JSON report may still change before 1.0. See the
> [design notes](docs/design.md) for how it works and what may come next.

## Install

On Linux (including Raspberry Pi OS) or macOS:

```sh
curl -fsSL https://raw.githubusercontent.com/joerao/eggprobe/main/install.sh | sh
```

No sudo, Rust toolchain or GitHub account needed. The installer picks the
right build for your system, verifies its SHA-256 checksum, and installs to
`~/.local/bin`. On Linux it adds that directory to your shell's PATH for
future terminals; for the current one, run the `export PATH=...` line it
prints, or start it directly with `"$HOME/.local/bin/eggprobe"`.

| System | Builds |
| --- | --- |
| Linux (static, any distribution) | x86-64, ARM64 |
| Raspberry Pi OS | ARM64, ARMv7, ARMv6 (Pi 1 / Zero) |
| macOS | Apple Silicon, Intel |

To update, run the same command again. To pin a version or install
elsewhere: `EGGPROBE_VERSION=v0.1.0 EGGPROBE_INSTALL_DIR="$HOME/bin" sh install.sh`.
To uninstall, delete the `eggprobe` binary; it keeps no other files.

To review the script first, download it and read it, then run `sh install.sh`.

## Try it

```sh
eggprobe                        # the interactive view
eggprobe --scan > scan.json     # or scan once and print JSON
```

From a source checkout with Rust 1.88 or newer, `make run` builds and
starts it.

Devices appear as they answer. A /24 takes about 25 seconds. Nothing needs
`sudo`. eggprobe does not install anything, change system settings, or keep
files between runs.

```sh
eggprobe --subnet 10.0.0.0/24            # instead of the default route's subnet
eggprobe --scan --interface wlan0            # scan from a particular interface
eggprobe --scan --skip mdns --skip port-probe --skip device-info
eggprobe --scan --mdns-listen 4
```

Exit codes: **0** complete, **1** a source failed, **2** invalid arguments,
**130** cancelled with Ctrl-C. A partial report is still printed for 1 and 130.

## Controls

| Key | Action |
| --- | --- |
| ↑ ↓ / j k, PgUp PgDn, g G | Move through devices |
| Enter / → | Open details (↑ ↓ then scroll them); Esc or ← goes back |
| Tab | Switch between the list and details |
| / | Filter by name, type, vendor, address or port |
| o | Sort by address, name, type, vendor or number of open ports |
| s | Stop the scan and keep what was found |
| r | Scan again |
| ? / q | Help / quit |

The mouse works too: click a row or a square in the subnet map, and scroll
with the wheel. Click a column heading to sort by it, and again to reverse.
Click a port number to open the service in your browser (or the handler for
`ssh://`, `smb://` and so on), addressed by the device's DNS or mDNS name when
it has one and its IP address otherwise. Terminals narrower than 120 columns
show the list only; Enter opens a device full screen.

## How it finds devices

Each source runs in turn, and all findings go to a single device table:

| Source | What it does | Privileges |
| --- | --- | --- |
| `tailscale` | Reads `tailscale status --json`: your tailnet's peers, their OS and online state | none |
| `tuya` | Listens, for the whole scan, for the broadcasts Tuya devices send on UDP 6666/6667; sends nothing | none |
| `neighbors` | Reads the kernel's ARP table (`ip neigh`, `/proc/net/arp`, or `arp -an`) | none |
| `tcp-sweep` | TCP connects to 5 common ports on every address, paced to avoid an ARP storm | none |
| `names` | Asks every host for its name three ways: reverse DNS through the router, NetBIOS, and mDNS sent straight to the device | none |
| `port-probe` | 46 service and homelab/IoT signature ports on every host that answered | none |
| `tailnet-probe` | The same signature ports on online tailnet peers that are not on this LAN, at their Tailscale address | none |
| `mdns` | DNS-SD meta-query, then known service types; records TXT data | none |
| `device-info` | Asks devices and servers with a known self-description API to describe themselves, over plain HTTP GET | none |

After the sweep, the ARP table holds a MAC for every host that answered ARP,
even hosts that drop all TCP. A host counts as **responding** only when
something heard from it during this run. A stale ARP entry is reported but not
counted as responding.

Every device carries an `evidence` list naming which source saw what.

## What devices say about themselves

Some devices describe themselves when asked. eggprobe asks the ones it
recognises and shows the answer under **Device reports**:

- **WLED** lights: name, firmware, LED and Wi-Fi status. Each WLED also
  lists the other WLEDs it has heard from, which finds some that mDNS missed.
- **Media servers** (Plex, Jellyfin, Emby) on their usual ports: name and
  version. These describe software on a host, so they are listed with the
  host rather than renaming it.
- **Tuya** devices broadcast an ID, a protocol version and a product key;
  devices with the same product key are listed as the same model.
- **mDNS TXT records**, with no extra traffic: the names and versions some
  devices publish there (Amazon media devices, Google Cast, ESPHome, Home
  Assistant, Matter).

A name a device gives itself is shown in preference to its hostname, except
factory defaults. Only `GET` requests are sent, to paths that describe a
device without changing it; redirects are not followed and no credentials
are used. A reply counts only when its content says what it is; a status
code alone is never evidence.

## What a device is

Each device gets a **vendor** from its MAC address (the IEEE registry is
embedded; randomized "private" addresses are recognised as such) and a
**classification**: a kind such as Printer, Camera, Phone/tablet or Smart
device, a product when something names it (a printer's model name, "WLED
lights"), a confidence (confident, likely, or a guess), and the reasons.
Strong evidence comes from what devices say about themselves: mDNS service
types, model identifiers, HomeKit categories, and the OS Tailscale reports.
Weaker evidence comes from vendors, open ports and hostnames. An HTTP status
code is never evidence on its own.

## Tailscale

If Tailscale is running, tailnet peers share the device list with the LAN.
A peer whose hostname matches exactly one LAN device's is linked to it: the
LAN device is marked `◇ tailnet`, shows its Tailscale address under its LAN
one, and the OS Tailscale reports feeds its classification. Peers not seen on
the LAN follow the LAN devices, with their OS and when they were last seen.

Online peers that are not on this LAN are probed at their Tailscale address:
the same signature ports and self-descriptions, so services on a remote
machine show up just as they would on the LAN. This
machine, peers already matched to a LAN device, and peers shared in from
someone else's tailnet are left out. Most tailnet traffic goes through a
relay, so this adds several seconds; `--skip tailnet-probe` turns it off.
If Tailscale is not installed or not connected, the Scan panel says so and
the rest of the scan is unaffected.

## Report shape

```json
{
  "eggprobe": "0.2.0",
  "target": { "interface": "wlan0", "address": "10.0.0.20",
              "gateway": "10.0.0.1", "subnet": "10.0.0.0/24" },
  "started": "2026-01-15T18:00:00Z", "elapsed_ms": 24120,
  "complete": true, "cancelled": false,
  "sources": [ { "name": "neighbors", "state": "done", "detail": "31 entries, 30 reachable, via ip neigh" } ],
  "stats": { "devices": 32, "responding": 30, "ignored_outside_subnet": 0, "tailnet_peers": 5 },
  "devices": [ { "ip": "10.0.0.45", "mac": "…", "hostname": "printer",
                 "responding": true, "is_self": false, "is_gateway": false,
                 "open_ports": [80, 443, 515, 631, 9100],
                 "mdns_services": [ { "service_type": "_ipp._tcp.local.", "instance": "Office Printer", "host": "printer.local", "port": 631, "txt": { "…": "…" } } ],
                 "info": [ { "protocol": "…", "from": "…", "name": "…", "product": "…",
                             "model": "…", "firmware": "…", "mac": null, "details": [ { "label": "…", "value": "…" } ] } ],
                 "evidence": [ { "source": "port-probe", "detail": "TCP 631 open" } ],
                 "first_seen": "2026-01-15T18:00:00Z", "last_seen": "2026-01-15T18:00:23Z",
                 "classification": { "kind": "printer", "product": "…",
                                     "confidence": "confident", "score": 99,
                                     "reasons": [ "advertises printing over mDNS (_ipp._tcp)", "…" ],
                                     "alternative": null, "vendor": { "kind": "known", "name": "…" } },
                 "tailnet": null } ],
  "tailnet": [ { "hostname": "…", "dns_name": "…", "os": "windows", "ips": [ "100.64.0.3" ],
                 "online": true, "shared_in": false, "lan_address": null,
                 "probed": { "open_ports": [ 3389, 8096 ], "info": [ { "…": "…" } ], "evidence": [ "…" ] },
                 "classification": { "…": "…" } } ]
}
```

Source states: `pending`, `running`, `done`, `unavailable` (cannot run here,
not an error), `failed`, `skipped`, `stopped` (cancelled; findings kept).

## Development

```sh
make test    # fmt check, clippy -D warnings, unit tests (including rendering), installer tests
make smoke   # headless scan of loopback only; safe in CI
```

### Releasing

Bump `version` in `Cargo.toml`, commit, then tag and push:

```sh
git tag v0.1.0 && git push origin v0.1.0
```

The Release workflow builds the four static Linux targets with
`cargo-zigbuild` and the two macOS targets natively, runs the ARM builds
under QEMU on Raspberry Pi CPUs, and publishes the archives with
`checksums.txt`, which `install.sh` verifies. The tag must match the
Cargo version. CI runs the same cross-build on every push.
`make release-linux` builds the Linux archives locally into `dist/`.

`scripts/capture.py` runs the real binary in a pseudo-terminal and saves PNG
screenshots to `target/capture/`, for checking the interface by eye:

```sh
python3 -m venv target/pyenv && target/pyenv/bin/pip install pyte pillow
make build && target/pyenv/bin/python scripts/capture.py 3 12 30
```

## License

MIT. See [LICENSE](LICENSE).
