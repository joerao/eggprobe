#!/usr/bin/env python3
"""Regenerate data/oui.tsv.gz from Wireshark's manufacturer database.

    python3 scripts/update_oui.py            # downloads the current file
    python3 scripts/update_oui.py manuf      # or uses a local copy

Output lines are `<hex prefix>\t<vendor>`, where the prefix has 6, 7 or 9 hex
digits for /24, /28 and /36 assignments. Vendor names are shortened for
display: "Tp-Link Technologies Co.,Ltd." becomes "TP-Link".
"""
import gzip
import re
import sys
import urllib.request
from pathlib import Path

SOURCE = "https://www.wireshark.org/download/automated/data/manuf"
OUT = Path(__file__).resolve().parents[1] / "data" / "oui.tsv.gz"

# Trailing words that say what kind of company it is, not which one.
SUFFIXES = {
    "inc", "incorporated", "corporation", "corp", "co", "company", "ltd", "limited",
    "llc", "l.l.c", "gmbh", "ag", "sa", "s.a", "sas", "s.p.a", "spa", "bv", "b.v", "nv",
    "pty", "pte", "plc", "oy", "ab", "a/s", "as", "kg", "kk", "srl", "s.r.l", "sl",
    "technologies", "technology", "tech", "electronics", "electronic", "international",
    "industrial", "industries", "industry", "manufacturing", "communications",
    "communication", "networks", "network", "systems", "system", "group", "holdings",
    "enterprise", "enterprises", "trading", "corporate", "solutions", "products",
    "devices", "labs", "semiconductor", "mobile", "digital", "america", "usa", "europe",
    "china", "japan", "korea", "taiwan", "shenzhen", "hk", "foundation", "incorporation",
    "device",
}

# Leading places that precede many registered names ("Zhejiang Dahua").
PLACES = {
    "beijing", "shanghai", "shenzhen", "guangzhou", "guangdong", "hangzhou", "zhejiang",
    "jiangsu", "fujian", "xiamen", "qingdao", "chongqing", "wuhan", "suzhou", "dongguan",
    "nanjing", "chengdu", "tianjin", "zhuhai", "foshan", "ningbo", "hefei", "sichuan",
    "shandong", "hubei", "hunan", "anhui", "henan", "jiangxi", "liaoning",
}

# Names people know better than the registered ones.
KNOWN = {
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "seiko epson": "Epson",
    "hon hai precision": "Foxconn",
    "hon hai precision ind": "Foxconn",
    "hewlett packard": "HP",
    "hewlett-packard": "HP",
    "hp": "HP",
    "lg": "LG",
    "lg innotek": "LG Innotek",
    "amazon": "Amazon",
    "ubiquiti": "Ubiquiti",
    "shelly": "Shelly",
    "allterco robotics": "Shelly",
    "signify netherlands": "Philips Hue",
    "philips lighting": "Philips Hue",
    "d-link": "D-Link",
    "asustek computer": "ASUS",
    "asustek": "ASUS",
    "zte": "ZTE",
    "texas instruments": "Texas Instruments",
    "vizio": "Vizio",
    "tuya smart": "Tuya",
    "hangzhou tuya": "Tuya",
    "beijing xiaomi": "Xiaomi",
    "xiaomi communications": "Xiaomi",
    "private": "",
}


def shorten(name: str) -> str:
    name = re.sub(r"\([^)]*\)", " ", name)          # "(Trading)", "(Shanghai)"
    name = name.replace(",", " ").replace("  ", " ")
    words = name.split()
    while len(words) > 1 and words[0].lower() in PLACES:
        words.pop(0)
    while len(words) > 1 and words[-1].lower().strip(".") in SUFFIXES:
        words.pop()
    short = " ".join(words).strip(" .-&")
    key = short.lower()
    for known, display in KNOWN.items():
        if key == known or key.startswith(known + " "):
            return display
    # Registry names are often all capitals; soften those that are long words.
    if short.isupper() and len(short) > 4:
        short = " ".join(w.capitalize() if len(w) > 3 else w for w in short.split())
    return short


def main() -> None:
    if len(sys.argv) > 1:
        text = Path(sys.argv[1]).read_text(encoding="utf-8")
    else:
        with urllib.request.urlopen(SOURCE, timeout=60) as r:
            text = r.read().decode("utf-8")
    rows = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        prefix, _, full = (p.strip() for p in parts[:3])
        bits = 24
        if "/" in prefix:
            prefix, b = prefix.split("/")
            bits = int(b)
        digits = {24: 6, 28: 7, 36: 9}.get(bits)
        if digits is None:
            continue  # other block sizes are not IEEE assignments
        hexs = prefix.replace(":", "").replace("-", "").upper()[:digits]
        vendor = shorten(full)
        if vendor and len(hexs) == digits:
            rows.append(f"{hexs}\t{vendor}")
    OUT.parent.mkdir(exist_ok=True)
    data = ("\n".join(sorted(set(rows))) + "\n").encode()
    OUT.write_bytes(gzip.compress(data, compresslevel=9, mtime=0))
    print(f"{OUT}: {len(rows)} prefixes, {len(data)} bytes raw, {OUT.stat().st_size} gzipped")


if __name__ == "__main__":
    main()
