#!/usr/bin/env python3
"""Exercise the real install.sh against local release fixtures.

Fakes uname, getconf, curl and gh; never uses the network.
"""
import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD = b"#!/bin/sh\nprintf 'eggprobe fixture\\n'\n"


def check(system, machine, arch, private=False, corrupt=False, bits="64", shell="bash", login=".profile"):
    with tempfile.TemporaryDirectory(prefix="eggprobe install test ") as td:
        root = Path(td).resolve()
        mocks, fixtures = root / "mocks", root / "fixtures"
        dest = root / "install dir's $literal `name`"
        home = root / "home"
        for d in (mocks, fixtures, dest, home):
            d.mkdir()
        (home / login).write_text("# Existing configuration\n")
        name = f"eggprobe_{'linux' if system == 'Linux' else 'darwin'}_{arch}.tar.gz"
        archive = fixtures / name
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo("eggprobe")
            info.size, info.mode = len(PAYLOAD), 0o755
            tar.addfile(info, io.BytesIO(PAYLOAD))
        digest = "0" * 64 if corrupt else hashlib.sha256(archive.read_bytes()).hexdigest()
        (fixtures / "checksums.txt").write_text(f"{digest}  {name}\n")
        (dest / "eggprobe").write_text("previous binary")
        scripts = {
            "uname": f'#!/bin/sh\ncase "$1" in -s) echo {system};; -m) echo {machine};; esac\n',
            "getconf": f"#!/bin/sh\necho {bits}\n",
            # A private repository's release URLs answer 404 to anonymous curl.
            "curl": '''#!/bin/sh
[ "$PRIVATE" = yes ] && exit 22
url=''; dest=''
while [ "$#" -gt 0 ]; do
 case "$1" in https:*) url=$1;; -o) shift; dest=$1;; esac
 shift
done
cp "$FIXTURES/${url##*/}" "$dest"
''',
            "gh": '''#!/bin/sh
[ "$PRIVATE" = yes ] || exit 1
if [ "$1" = auth ]; then exit 0; fi
dest=''
while [ "$#" -gt 0 ]; do
 if [ "$1" = --dir ]; then shift; dest=$1; fi
 shift
done
cp "$FIXTURES/"* "$dest/"
''',
        }
        for script, content in scripts.items():
            p = mocks / script
            p.write_text(content)
            p.chmod(0o755)
        env = dict(os.environ, PATH=f"{mocks}:/usr/bin:/bin", FIXTURES=str(fixtures),
                   HOME=str(home), SHELL=f"/bin/{shell}", ZDOTDIR=str(home),
                   PRIVATE="yes" if private else "no", EGGPROBE_INSTALL_DIR=str(dest),
                   EGGPROBE_VERSION="v0.1.0", EGGPROBE_REPO="example/eggprobe")
        run = lambda: subprocess.run(["sh", str(ROOT / "install.sh")], env=env, capture_output=True, text=True)
        result = run()
        if corrupt:
            assert result.returncode != 0, result.stdout
            assert "checksum" in result.stderr, result.stderr
            assert (dest / "eggprobe").read_text() == "previous binary", "failed install replaced the existing binary"
            return
        assert result.returncode == 0, result.stdout + result.stderr
        assert os.access(dest / "eggprobe", os.X_OK)
        assert (dest / "eggprobe").read_bytes() == PAYLOAD
        assert not list(dest.glob(".eggprobe.*")), "staging file left behind"
        if system == "Linux":
            profiles = ([home / login, home / ".bashrc"] if shell == "bash"
                        else [home / (".zshrc" if shell == "zsh" else ".profile")])
            before = [p.read_text() for p in profiles]
            repeat = run()
            assert repeat.returncode == 0, repeat.stderr
            assert before == [p.read_text() for p in profiles], "duplicate PATH entries on reinstall"
            for profile in profiles:
                probe = subprocess.run(
                    ["sh", "-c", '. "$1"; . "$1"; command -v eggprobe; printf "%s\\n" "$PATH"', "sh", str(profile)],
                    env=env, capture_output=True, text=True)
                assert probe.returncode == 0, probe.stderr
                lines = probe.stdout.splitlines()
                assert lines[0] == str(dest / "eggprobe"), probe.stdout
                assert lines[1].split(":").count(str(dest)) == 1, probe.stdout
        else:
            assert (home / login).read_text() == "# Existing configuration\n", "macOS profiles are left alone"
            assert not (home / ".bashrc").exists()


cases = 0
for system, machine, arch in [("Linux", "x86_64", "amd64"), ("Linux", "aarch64", "arm64"),
                              ("Linux", "armv6l", "armv6"), ("Linux", "armv7l", "armv7"),
                              ("Darwin", "arm64", "arm64"), ("Darwin", "x86_64", "amd64")]:
    check(system, machine, arch); cases += 1
check("Linux", "aarch64", "armv7", bits="32"); cases += 1     # 64-bit kernel, 32-bit Pi userland
check("Linux", "armv8l", "armv7", bits="32"); cases += 1
check("Linux", "arm64", "arm64"); cases += 1
check("Linux", "x86_64", "amd64", private=True); cases += 1   # gh fallback
check("Linux", "x86_64", "amd64", corrupt=True); cases += 1   # checksum mismatch
for login in (".bash_profile", ".bash_login"):
    check("Linux", "aarch64", "arm64", login=login); cases += 1
for shell in ("sh", "zsh"):
    check("Linux", "armv7l", "armv7", shell=shell); cases += 1
print(f"Installer: all {cases} platform/authentication/checksum/PATH cases passed")
