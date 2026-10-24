#!/bin/sh
# AWMZA Security agent installer for macOS and Linux - no Python needed.
#   curl -fsSL https://security.awmza.com/agent/install.sh | sudo sh -s -- --token awe_...
#   upgrade (keeps the device): curl -fsSL https://security.awmza.com/agent/install.sh | sudo sh
# The binary is checked against SHA256SUMS before it runs. Files fetched by curl get no
# quarantine flag, so macOS Gatekeeper does not block the (ad-hoc signed) binary.
set -eu
BASE="${AWMZA_AGENT_BASE:-https://security.awmza.com/agent}"
TOKEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --token) TOKEN="${2:-}"; shift 2 ;;
    --token=*) TOKEN="${1#*=}"; shift ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done
case "$TOKEN" in ""|awe_*) ;; *) echo "The token must start with awe_ (copy it from the dashboard)." >&2; exit 2 ;; esac
[ "$(id -u)" = 0 ] || { echo "Run with sudo." >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) F=awmza-agent-macos-arm64 ;;
  Darwin-x86_64) F=awmza-agent-macos-x86_64 ;;
  Linux-x86_64|Linux-amd64) F=awmza-agent-linux-x86_64 ;;
  *) echo "This computer is not supported yet: $(uname -s) $(uname -m)" >&2; exit 1 ;;
esac

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
PROTO='=https'
case "$BASE" in file://*) PROTO='=file' ;; esac  # local test mirror only
get() { curl -fsSL --proto "$PROTO" --tlsv1.2 --retry 3 -o "$TMP/$1" "$BASE/$1"; }
get "$F"
get SHA256SUMS
WANT=$(awk -v f="$F" '$2 == f || $2 == "*" f { print $1 }' "$TMP/SHA256SUMS")
if command -v sha256sum >/dev/null 2>&1; then HAVE=$(sha256sum "$TMP/$F" | awk '{print $1}')
else HAVE=$(shasum -a 256 "$TMP/$F" | awk '{print $1}'); fi
if [ -z "$WANT" ] || [ "$WANT" != "$HAVE" ]; then
  echo "SHA-256 check failed for $F - not installing." >&2; exit 1
fi
chmod 700 "$TMP/$F"
# the agent copies itself to a root-only folder and starts the service from there
if [ -n "$TOKEN" ]; then "$TMP/$F" install --token "$TOKEN"; else "$TMP/$F" service; fi
