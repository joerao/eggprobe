#!/bin/sh
# Run the Linux ARM release binaries under QEMU user-mode emulation, on the
# CPUs of real Raspberry Pis: ARM1176 (Pi 1, Zero), Cortex-A7 (Pi 2),
# Cortex-A53 (Pi 3 and later, 64-bit). Needs qemu-user; used in CI.
set -eu
fail=0
check() {
 qemu=$1; cpu=$2; archive=$3
 stage=$(mktemp -d)
 tar -xzf "dist/$archive" -C "$stage" eggprobe
 if version=$("$qemu" -cpu "$cpu" "$stage/eggprobe" --version) &&
  "$qemu" -cpu "$cpu" "$stage/eggprobe" --scan --subnet 127.0.0.1/32 --skip mdns --skip tailscale |
  python3 -c 'import json,sys; r=json.load(sys.stdin); assert r["complete"], r'
 then
  echo "ok   $archive on $cpu: $version"
 else
  echo "FAIL $archive on $cpu"; fail=1
 fi
 rm -rf "$stage"
}
check qemu-arm arm1176 eggprobe_linux_armv6.tar.gz
check qemu-arm cortex-a7 eggprobe_linux_armv7.tar.gz
check qemu-aarch64 cortex-a53 eggprobe_linux_arm64.tar.gz
exit $fail
