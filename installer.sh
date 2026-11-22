#!/usr/bin/env bash
# sm installer: commands, optional server (+ autostart), or pairing with a
# server on another machine, then the agent skill and the GitHub git helper.
#
#   ./installer.sh                      interactive
#   ./installer.sh --server [--lan IP] [--tls-cert F --tls-key F --tls-ca F | --gen-tls]
#   ./installer.sh --client --server-url https://HOST:8737 --code XXXX-XXXX [--ca-fingerprint SHA256]
# Options: --bin DIR (where the commands go), --yes (accept defaults),
#          --no-skill, --no-git, --no-service (server: don't install the systemd unit)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="" YES=0 SKILL="" GIT="" SERVICE=1 LAN="" CERT="" KEY="" CA="" GEN_TLS=0
SERVER_URL="" CODE="" CA_FP="" BIN_DIR="" PORT="${SM_PORT:-8737}"

while [ $# -gt 0 ]; do
  case "$1" in
    --server) MODE=server ;;
    --client) MODE=client ;;
    --server-url) SERVER_URL="$2"; shift ;;
    --code) CODE="$2"; shift ;;
    --ca-fingerprint) CA_FP="$2"; shift ;;
    --lan) LAN="$2"; shift ;;
    --tls-cert) CERT="$2"; shift ;;
    --tls-key) KEY="$2"; shift ;;
    --tls-ca) CA="$2"; shift ;;
    --gen-tls) GEN_TLS=1 ;;
    --port) PORT="$2"; shift ;;
    --bin) BIN_DIR="$2"; shift ;;
    --yes|-y) YES=1 ;;
    --no-skill) SKILL=no ;;
    --no-git) GIT=no ;;
    --no-service) SERVICE=0 ;;
    -h|--help) sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

bold() { printf '\e[1m%s\e[0m\n' "$*"; }
info() { printf '  %s\n' "$*"; }
die() { printf '\e[31merror:\e[0m %s\n' "$*" >&2; exit 1; }
ask() { # ask "question" default -> REPLY
  local q=$1 def=${2:-}
  if [ "$YES" = 1 ] || [ ! -t 0 ]; then REPLY=$def; return; fi
  read -r -p "$q${def:+ [$def]} " REPLY
  REPLY=${REPLY:-$def}
}
yesno() { # yesno "question" y|n -> 0 for yes
  local def=$2
  ask "$1 [y/n]" "$def"
  [[ "$REPLY" =~ ^[Yy] ]]
}

# ---------- 1. Node and the commands ----------
bold "1. Commands"
NODE="$(command -v node || true)"
[ -n "$NODE" ] || die "node not found (Node.js 20 or newer is needed)"
NODE="$(readlink -f "$NODE")"
NODE_MAJOR="$("$NODE" -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 20 ] || die "Node.js $NODE_MAJOR found, 20 or newer is needed"
info "node $("$NODE" -v) at $NODE"
if [ ! -d "$REPO/node_modules/express" ]; then
  info "installing dependencies (npm ci)"
  (cd "$REPO" && npm ci --omit=dev --no-audit --no-fund >/dev/null)
fi
if [ -z "$BIN_DIR" ]; then
  if [ "$(id -u)" = 0 ]; then BIN_DIR=/usr/local/bin; else BIN_DIR="$HOME/.local/bin"; fi
fi
mkdir -p "$BIN_DIR"
# Small wrappers with the absolute node path: they work in systemd units and
# shells where node isn't on PATH (nvm).
for cmd in sm smctl sm-ls sm-add sm-server git-credential-sm; do
  src="$REPO/bin/$cmd.js"; [ "$cmd" = sm-server ] && src="$REPO/server/index.js"
  printf '#!/bin/sh\nexec "%s" "%s" "$@"\n' "$NODE" "$src" > "$BIN_DIR/$cmd"
  chmod 755 "$BIN_DIR/$cmd"
done
info "installed sm, smctl, sm-ls, sm-add, sm-server, git-credential-sm in $BIN_DIR"
case ":$PATH:" in *":$BIN_DIR:"*) ;; *) info "note: add $BIN_DIR to your PATH" ;; esac
SMCTL="$BIN_DIR/smctl"

# ---------- 2. Server here, or pair with one elsewhere ----------
if [ -z "$MODE" ]; then
  if yesno "Run the sm server (secret store + GUI) on THIS machine?" n; then MODE=server; else MODE=client; fi
fi

if [ "$MODE" = server ]; then
  bold "2. Server"
  DATA="${SM_SERVER_DATA:-$REPO/.sm-server}"
  if [ -z "$LAN" ] && [ -z "$CERT" ] && [ "$GEN_TLS" = 0 ]; then
    if yesno "Also serve the GUI on your network over HTTPS (needed for other machines)?" y; then
      ask "IP address to listen on" "$(hostname -I 2>/dev/null | awk '{print $1}')"; LAN=$REPLY
      ask "TLS certificate file (empty = generate a local CA + certificate)" ""; CERT=$REPLY
      if [ -n "$CERT" ]; then
        ask "TLS key file" ""; KEY=$REPLY
        ask "CA certificate that signed it (optional, lets other machines trust it)" ""; CA=$REPLY
      else GEN_TLS=1; fi
    fi
  fi
  if [ -n "$LAN" ] && [ "$GEN_TLS" = 1 ]; then
    command -v openssl >/dev/null || die "openssl is needed to generate certificates"
    T="$DATA/tls"; mkdir -p "$T"; chmod 700 "$DATA" "$T"
    if [ ! -f "$T/ca.key" ]; then
      openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=sm local CA" -keyout "$T/ca.key" -out "$T/ca.crt" 2>/dev/null
    fi
    openssl req -newkey rsa:2048 -nodes -subj "/CN=$LAN" -keyout "$T/server.key" -out "$T/server.csr" 2>/dev/null
    printf 'subjectAltName=IP:%s,IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n' "$LAN" > "$T/ext.cnf"
    openssl x509 -req -in "$T/server.csr" -CA "$T/ca.crt" -CAkey "$T/ca.key" -CAcreateserial -days 825 -extfile "$T/ext.cnf" -out "$T/server.crt" 2>/dev/null
    rm -f "$T/server.csr" "$T/ext.cnf" "$T/ca.srl"
    chmod 600 "$T"/*.key
    CERT="$T/server.crt" KEY="$T/server.key" CA="$T/ca.crt"
    info "generated a local CA and a certificate for $LAN in $T"
  fi
  [ -z "$LAN" ] || { [ -f "$CERT" ] && [ -f "$KEY" ]; } || die "certificate or key file not found"

  ENVLINES="Environment=SM_PORT=$PORT\nEnvironment=SM_SERVER_DATA=$DATA"
  [ -n "$LAN" ] && ENVLINES="$ENVLINES\nEnvironment=SM_LAN_BIND=$LAN\nEnvironment=SM_TLS_CERT=$CERT\nEnvironment=SM_TLS_KEY=$KEY"
  [ -n "$CA" ] && ENVLINES="$ENVLINES\nEnvironment=SM_TLS_CA=$CA"
  UNIT="[Unit]
Description=sm secret manager (API + GUI)
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO
ExecStart=$NODE $REPO/server/index.js
$(printf "$ENVLINES")
# The LAN address may come up a little after boot: retry.
Restart=on-failure
RestartSec=5
UMask=0077
"
  if [ "$SERVICE" = 0 ]; then
    info "--no-service: unit not installed. It would be:"; printf '%s\n' "$UNIT" | sed 's/^/    /'
  elif ! command -v systemctl >/dev/null; then
    info "systemd not found: start the server yourself with: sm-server (env as below)"; printf '%s\n' "$UNIT" | grep Environment | sed 's/^/    /'
  else
    if [ "$(id -u)" = 0 ]; then
      UNIT_FILE=/etc/systemd/system/sm-server.service; SC=(systemctl)
      UNIT="$UNIT
[Install]
WantedBy=multi-user.target"
    else
      UNIT_FILE="$HOME/.config/systemd/user/sm-server.service"; SC=(systemctl --user)
      UNIT="$UNIT
[Install]
WantedBy=default.target"
      mkdir -p "$(dirname "$UNIT_FILE")"
      loginctl enable-linger "$USER" 2>/dev/null || info "note: run 'loginctl enable-linger $USER' so it starts at boot without a login"
    fi
    if [ -f "$UNIT_FILE" ] && ! cmp -s <(printf '%s\n' "$UNIT") "$UNIT_FILE"; then
      cp "$UNIT_FILE" "$UNIT_FILE.bak-$(date +%Y%m%d%H%M%S)"; info "previous unit saved as $UNIT_FILE.bak-*"
    fi
    printf '%s\n' "$UNIT" > "$UNIT_FILE"
    "${SC[@]}" daemon-reload
    "${SC[@]}" enable sm-server.service >/dev/null 2>&1
    "${SC[@]}" restart sm-server.service
    info "systemd unit $UNIT_FILE: enabled at boot, (re)started"
    for _ in $(seq 1 40); do curl -sf "http://127.0.0.1:$PORT/health" >/dev/null 2>&1 && break; sleep 0.25; done
    curl -sf "http://127.0.0.1:$PORT/health" >/dev/null || die "server did not come up: ${SC[*]} status sm-server"
  fi
  if [ "$SERVICE" = 1 ] && command -v systemctl >/dev/null; then
    SM_SERVER_DATA="$DATA" "$SMCTL" login --server "http://127.0.0.1:$PORT" ${LAN:+--gui-url "https://$LAN:$PORT"}
    info "GUI: ${LAN:+https://$LAN:$PORT (network) and }http://127.0.0.1:$PORT (this machine). The first visit asks you to set a password."
    info "other machines: run 'smctl pair' here, then the installer there with --client"
  fi

else
  bold "2. Connect to a server on another machine"
  [ -n "$SERVER_URL" ] || { ask "Server URL (e.g. https://192.168.1.10:8737)" ""; SERVER_URL=$REPLY; }
  [ -n "$SERVER_URL" ] || die "a server URL is needed"
  [ -n "$CODE" ] || { info "on the server run:  smctl pair"; ask "Pairing code" ""; CODE=$REPLY; }
  [ -n "$CODE" ] || die "a pairing code is needed"
  "$SMCTL" login --server "$SERVER_URL" --code "$CODE" ${CA_FP:+--ca-fingerprint "$CA_FP"}
  "$SMCTL" status
fi

# ---------- 3. Agent skill + global instructions ----------
if [ "$SKILL" != no ] && { [ "$SKILL" = yes ] || yesno "Install the secret-manager skill for Claude Code and opencode?" y; }; then
  bold "3. Agent skill"
  for dir in "$HOME/.claude/skills" "$HOME/.config/opencode/skills"; do
    mkdir -p "$dir"
    if [ -e "$dir/secret-manager" ] && [ ! -L "$dir/secret-manager" ]; then mv "$dir/secret-manager" "$dir/secret-manager.bak-$(date +%s)"; fi
    ln -sfn "$REPO/skills/secret-manager" "$dir/secret-manager"
    info "linked $dir/secret-manager"
  done
  if yesno "Also announce it at the start of every agent conversation (global CLAUDE.md / AGENTS.md)?" y; then
    for f in "$HOME/.claude/CLAUDE.md" "$HOME/.config/opencode/AGENTS.md"; do
      mkdir -p "$(dirname "$f")"; touch "$f"
      if grep -q 'secret-manager (sm)' "$f"; then info "$f already has it"; else
        [ -s "$f" ] && printf '\n' >> "$f"; cat "$REPO/skills/global-instructions.md" >> "$f"; info "added to $f"; fi
    done
  fi
fi

# ---------- 4. GitHub through sm ----------
if [ "$GIT" != no ] && command -v git >/dev/null && { [ "$GIT" = yes ] || yesno "Let git get the GitHub token (secret GITHUB_TOKEN) from sm? push/pull then run as: sm -c 'git push'" y; }; then
  bold "4. git"
  HELPER="!$NODE $REPO/bin/git-credential-sm.js"
  cp -n "$HOME/.gitconfig" "$HOME/.gitconfig.before-sm" 2>/dev/null || true
  for host in https://github.com https://gist.github.com; do
    git config --global --unset-all "credential.$host.helper" 2>/dev/null || true
    git config --global --add "credential.$host.helper" ''
    git config --global --add "credential.$host.helper" "$HELPER"
  done
  info "git credential helper for github.com = git-credential-sm (answers only inside sm)"
  info "store the token once, if not done yet:  printf %s \"\$TOKEN\" | sm-add GITHUB_TOKEN --category GitHub"
fi

bold "Done."
info "Try:  sm-ls    sm -c 'echo \$SOME_SECRET'    smctl status"
