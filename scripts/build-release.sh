#!/bin/sh
# Build release archives into dist/.
#
#   scripts/build-release.sh v0.1.0 linux     # the four Linux targets (needs cargo-zigbuild)
#   scripts/build-release.sh v0.1.0 darwin    # both macOS targets (run on macOS)
#   scripts/build-release.sh v0.1.0 checksums # checksums.txt for everything in dist/
#
# Linux builds are static (musl), so they run on any distribution, including
# Raspberry Pi OS. Archive names match install.sh: eggprobe_<os>_<arch>.tar.gz
set -eu
version=${1:?usage: build-release.sh VERSION linux|darwin|checksums}
what=${2:?usage: build-release.sh VERSION linux|darwin|checksums}
cargo_version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n 1)
case "$version" in
 v*) [ "$version" = "v$cargo_version" ] || { echo "tag $version does not match Cargo.toml version $cargo_version" >&2; exit 1; } ;;
esac
mkdir -p dist

package() {
 os=$1; arch=$2; binary=$3
 stage=$(mktemp -d)
 cp "$binary" "$stage/eggprobe"
 cp README.md "$stage/"
 cp -R docs "$stage/docs"
 tar -czf "dist/eggprobe_${os}_${arch}.tar.gz" -C "$stage" eggprobe README.md docs
 rm -rf "$stage"
 echo "dist/eggprobe_${os}_${arch}.tar.gz"
}

case "$what" in
 linux)
  for pair in amd64:x86_64-unknown-linux-musl arm64:aarch64-unknown-linux-musl \
              armv7:armv7-unknown-linux-musleabihf armv6:arm-unknown-linux-musleabihf; do
   arch=${pair%%:*}; target=${pair#*:}
   cargo zigbuild --release --locked --target "$target"
   package linux "$arch" "target/$target/release/eggprobe"
  done
  ;;
 darwin)
  for pair in arm64:aarch64-apple-darwin amd64:x86_64-apple-darwin; do
   arch=${pair%%:*}; target=${pair#*:}
   cargo build --release --locked --target "$target"
   package darwin "$arch" "target/$target/release/eggprobe"
  done
  ;;
 checksums)
  (cd dist && for f in eggprobe_*.tar.gz; do
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$f"; else shasum -a 256 "$f"; fi
   done > checksums.txt)
  cat dist/checksums.txt
  ;;
 *) echo "unknown build: $what" >&2; exit 2 ;;
esac
