#!/usr/bin/env bash
# One-line install of sm (secret manager):
#
#   curl -fsSL https://raw.githubusercontent.com/lethevimlet/secret-manager/main/install.sh | bash
#
# Installs Node.js with nvm if needed, the npm package @lethevimlet/secret-manager,
# then runs its installer (commands on PATH, server or pairing, coding agents,
# git). Installer options go after "bash -s --", e.g.
#
#   curl -fsSL …/install.sh | bash -s -- --client --server-url https://HOST:8737 --code XXXX-XXXX
#
# Run it again to update. SM_PACKAGE=<npm spec> installs another version or a tarball.
set -euo pipefail
PKG="${SM_PACKAGE:-@lethevimlet/secret-manager}"
NVM_VERSION=v0.40.3

say() { printf '\e[1m%s\e[0m\n' "$*"; }
die() { printf '\e[31merror:\e[0m %s\n' "$*" >&2; exit 1; }

# Questions come from the terminal even though this script arrives on stdin.
TTY=/dev/null
if [ -t 0 ]; then TTY=/dev/stdin; elif (exec </dev/tty) 2>/dev/null; then TTY=/dev/tty; fi
YES=0; for a in "$@"; do case "$a" in --yes|-y) YES=1 ;; esac; done

set +u
node_ok() { command -v node >/dev/null && [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 20 ]; }
export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
if ! node_ok && [ -s "$NVM_DIR/nvm.sh" ]; then
  . "$NVM_DIR/nvm.sh" >/dev/null 2>&1 || true
  node_ok || nvm use --lts >/dev/null 2>&1 || nvm use default >/dev/null 2>&1 || true
fi
if ! node_ok; then
  have=$(command -v node >/dev/null && node -v || echo "not installed")
  if [ "$YES" = 0 ] && [ "$TTY" != /dev/null ]; then
    read -r -p "sm needs Node.js 20+ (found: $have). Install the current LTS with nvm in ~/.nvm (no root needed)? [Y/n] " r <"$TTY"
    [[ "${r:-y}" =~ ^[Yy] ]] || die "Node.js 20 or newer is needed"
  fi
  command -v curl >/dev/null || die "curl is needed"
  if ! command -v nvm >/dev/null 2>&1; then
    say "Installing nvm $NVM_VERSION"
    curl -fsSL "https://raw.githubusercontent.com/nvm-sh/nvm/$NVM_VERSION/install.sh" | bash >/dev/null
    . "$NVM_DIR/nvm.sh" || die "nvm did not install"
  fi
  say "Installing Node.js LTS"
  nvm install --lts >/dev/null && nvm alias default 'lts/*' >/dev/null
  node_ok || die "Node.js install failed"
fi
set -u
say "Node.js $(node -v)"

# A global npm install needs a writable prefix; without one (system Node as a
# normal user) use a private prefix.
PREFIX="${NPM_CONFIG_PREFIX:-${npm_config_prefix:-$(node -p 'require("path").resolve(process.execPath, "../..")')}}"
if [ ! -w "$PREFIX/lib" ] && [ ! -w "$PREFIX" ]; then
  PREFIX="$HOME/.local/share/sm/npm"; mkdir -p "$PREFIX"
fi
say "Installing $PKG"
npm install -g --prefix "$PREFIX" --no-audit --no-fund "$PKG" >/dev/null
DIR="$PREFIX/lib/node_modules/@lethevimlet/secret-manager"
[ -x "$DIR/installer.sh" ] || die "package installed, but $DIR/installer.sh is missing"

exec bash "$DIR/installer.sh" "$@" <"$TTY"
