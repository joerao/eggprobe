#!/usr/bin/env python3
"""Run eggprobe in a real pseudo-terminal and save PNG screenshots.

Development only. Needs pyte and Pillow, and a DejaVu Sans Mono font:

    python3 -m venv target/pyenv
    target/pyenv/bin/pip install pyte pillow
    make build
    target/pyenv/bin/python scripts/capture.py 3 12 30

Each argument is a number of seconds after launch; one PNG is written per
argument to target/capture/. Keys can be sent between shots with k:<keys>,
for example `3 k:jjj 4 k:? 5`.
"""
import fcntl
import os
import pty
import select
import signal
import struct
import sys
import termios
import time
from pathlib import Path

import pyte
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
COLS, ROWS = int(os.environ.get("COLS", 150)), int(os.environ.get("ROWS", 42))
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
SIZE = 15
BG = (0x1a, 0x1b, 0x26)
FG = (0xc0, 0xca, 0xf5)
NAMED = {
    "black": (0x15, 0x16, 0x1e), "red": (0xf7, 0x76, 0x8e), "green": (0x9e, 0xce, 0x6a),
    "brown": (0xe0, 0xaf, 0x68), "blue": (0x7a, 0xa2, 0xf7), "magenta": (0xbb, 0x9a, 0xf7),
    "cyan": (0x7d, 0xcf, 0xff), "white": (0xa9, 0xb1, 0xd6),
}


def color(value, default):
    if value == "default":
        return default
    if value in NAMED:
        return NAMED[value]
    try:
        return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))
    except (ValueError, TypeError):
        return default


def render(screen, path):
    font = ImageFont.truetype(FONT, SIZE)
    bold = ImageFont.truetype(FONT_BOLD, SIZE)
    cw = int(font.getlength("M"))
    ch = SIZE + 4
    img = Image.new("RGB", (COLS * cw + 24, ROWS * ch + 24), BG)
    draw = ImageDraw.Draw(img)
    for y in range(ROWS):
        line = screen.buffer[y]
        for x in range(COLS):
            c = line[x]
            fg, bg = color(c.fg, FG), color(c.bg, BG)
            if c.reverse:
                fg, bg = bg, fg
            px, py = 12 + x * cw, 12 + y * ch
            if bg != BG:
                draw.rectangle([px, py, px + cw - 1, py + ch - 1], fill=bg)
            if c.data.strip():
                draw.text((px, py + 1), c.data, font=bold if c.bold else font, fill=fg)
    img.save(path)


def main(steps):
    out = ROOT / "target" / "capture"
    out.mkdir(parents=True, exist_ok=True)
    screen = pyte.Screen(COLS, ROWS)
    stream = pyte.ByteStream(screen)
    pid, fd = pty.fork()
    if pid == 0:
        os.environ.update(TERM="xterm-256color", COLORTERM="truecolor")
        os.execv(str(ROOT / "target/release/eggprobe"), ["eggprobe", *os.environ.get("ARGS", "").split()])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    start = time.time()
    shot = 0

    def pump(until):
        while time.time() < until:
            r, _, _ = select.select([fd], [], [], 0.05)
            if r:
                try:
                    stream.feed(os.read(fd, 65536))
                except OSError:
                    return

    for step in steps:
        if step.startswith("k:"):
            for key in step[2:].replace("\\n", "\r"):
                os.write(fd, key.encode())
                pump(time.time() + 0.15)
            continue
        pump(start + float(step))
        shot += 1
        path = out / f"shot{shot}.png"
        render(screen, path)
        print(path)
    os.write(fd, b"q")
    pump(time.time() + 0.5)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass


if __name__ == "__main__":
    main(sys.argv[1:] or ["3", "12", "30"])
