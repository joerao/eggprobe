#!/bin/sh
# Install a published eggprobe binary. No root, Rust toolchain or GitHub
# account needed:
#
#   curl -fsSL https://raw.githubusercontent.com/joerao/eggprobe/main/install.sh | sh
#
# EGGPROBE_VERSION (default latest), EGGPROBE_INSTALL_DIR (default
# ~/.local/bin) and EGGPROBE_REPO override the defaults.
set -eu
REPO=${EGGPROBE_REPO:-joerao/eggprobe}
VERSION=${EGGPROBE_VERSION:-latest}
DEST=${EGGPROBE_INSTALL_DIR:-"$HOME/.local/bin"}
fail() { printf '%s\n' "eggprobe: $*" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || fail 'curl is required'
command -v tar >/dev/null 2>&1 || fail 'tar is required'
case "$(uname -s)" in
 Linux) os=linux ;;
 Darwin) os=darwin ;;
 *) fail 'supported systems: Linux, macOS, Raspberry Pi OS' ;;
esac
case "$(uname -m)" in
 x86_64|amd64) arch=amd64 ;;
 aarch64|arm64) arch=arm64 ;;
 armv7l|armv8l) arch=armv7 ;;
 armv6l) arch=armv6 ;;
 *) fail "unsupported architecture: $(uname -m)" ;;
esac
# A 32-bit Pi userland can run under a 64-bit kernel.
if [ "$os" = linux ] && [ "$arch" = arm64 ] && command -v getconf >/dev/null 2>&1; then
 if [ "$(getconf LONG_BIT)" = 32 ]; then arch=armv7; fi
fi
case "$os/$arch" in darwin/armv6|darwin/armv7) fail 'unsupported macOS architecture' ;; esac
asset="eggprobe_${os}_${arch}.tar.gz"
tmp=$(mktemp -d)
staged=''
cleanup() { rm -rf "$tmp"; if [ -n "$staged" ]; then rm -f "$staged"; fi; }
trap cleanup EXIT HUP INT TERM
if [ "$VERSION" = latest ]; then base="https://github.com/$REPO/releases/latest/download"; else base="https://github.com/$REPO/releases/download/$VERSION"; fi
if curl --proto '=https' --tlsv1.2 -fsSL "$base/$asset" -o "$tmp/$asset" 2>/dev/null; then
 curl --proto '=https' --tlsv1.2 -fsSL "$base/checksums.txt" -o "$tmp/checksums.txt" || fail 'checksum download failed'
elif command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
 # Private repositories: fall back to an authenticated GitHub CLI.
 if [ "$VERSION" = latest ]; then
  gh release download --repo "$REPO" --pattern "$asset" --pattern checksums.txt --dir "$tmp" || fail 'release download failed; ensure repository access and a published release'
 else
  gh release download "$VERSION" --repo "$REPO" --pattern "$asset" --pattern checksums.txt --dir "$tmp" || fail 'release download failed'
 fi
else
 fail "could not download $asset from $base; check the version, or run gh auth login for a private repository"
fi
awk -v asset="$asset" '$2 == asset {print}' "$tmp/checksums.txt" > "$tmp/selected.sha256"
[ "$(wc -l < "$tmp/selected.sha256" | tr -d ' ')" = 1 ] || fail 'missing or ambiguous checksum'
if command -v sha256sum >/dev/null 2>&1; then
 (cd "$tmp" && sha256sum -c selected.sha256 >/dev/null) || fail 'checksum mismatch'
elif command -v shasum >/dev/null 2>&1; then
 (cd "$tmp" && shasum -a 256 -c selected.sha256 >/dev/null) || fail 'checksum mismatch'
else
 fail 'sha256sum or shasum is required'
fi
tar -xzf "$tmp/$asset" -C "$tmp" eggprobe
[ -f "$tmp/eggprobe" ] && [ ! -L "$tmp/eggprobe" ] || fail 'archive does not contain a regular binary'
mkdir -p "$DEST"
staged=$(mktemp "$DEST/.eggprobe.XXXXXX")
cp "$tmp/eggprobe" "$staged"
chmod 755 "$staged"
mv -f "$staged" "$DEST/eggprobe"
staged=''
# Use an absolute, shell-quoted path so spaces and shell metacharacters are safe.
DEST=$(cd "$DEST" && pwd -P)
quoted_dest=$(printf '%s' "$DEST" | sed "s/'/'\\\\''/g")
path_command="export PATH='$quoted_dest':\$PATH"
startup_files=''
if [ "$os" = linux ]; then
 # Bash login shells read only the first existing profile in this order.
 # Interactive non-login shells (including desktop terminals) read .bashrc.
 shell_name=${SHELL:-sh}
 case "${shell_name##*/}" in
  bash)
   profile="$HOME/.profile"
   if [ -f "$HOME/.bash_profile" ]; then profile="$HOME/.bash_profile"
   elif [ -f "$HOME/.bash_login" ]; then profile="$HOME/.bash_login"; fi
   startup_files="$profile
$HOME/.bashrc"
   ;;
  zsh) startup_files="${ZDOTDIR:-$HOME}/.zshrc" ;;
  sh|dash|'') startup_files="$HOME/.profile" ;;
  *) startup_files='' ;;
 esac
 # A guarded entry is safe when both a profile and an rc file are sourced.
 path_entry="case \":\$PATH:\" in *:'$quoted_dest':*) ;; *) $path_command ;; esac"
 printf '%s\n' "$startup_files" | while IFS= read -r profile; do
  [ -n "$profile" ] || continue
  if ! grep -Fqx "$path_entry" "$profile" 2>/dev/null; then
   if printf '\n# Added by the eggprobe installer.\n%s\n' "$path_entry" >> "$profile"; then
    printf 'Updated PATH in %s\n' "$profile"
   else
    printf 'Could not update %s; add this manually: %s\n' "$profile" "$path_command" >&2
   fi
  fi
 done
fi
printf '\nInstalled %s (%s)\n' "$DEST/eggprobe" "$("$DEST/eggprobe" --version 2>/dev/null || echo "$os/$arch")"
case ":$PATH:" in *":$DEST:"*) ;; *)
 printf 'For this terminal, run: %s\n' "$path_command"
 if [ "$os" != linux ] || [ -z "$startup_files" ]; then
  printf 'Also add that command to your shell profile for future sessions.\n'
 fi
 ;; esac
printf 'Run eggprobe to scan your network. No sudo needed.\n'
