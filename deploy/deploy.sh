#!/bin/sh
# Publishes a CI-built agent release (the "agent-release" artifact or a GitHub release) to security.awmza.com/agent/.
# usage: sh deploy.sh /path/to/release-dir   (must contain SHA256SUMS and the files it lists)
# Live copy on the server: /opt/awmza-build/agent-release/deploy.sh
set -eu
SRC="$1"; DST=/var/www/security.awmza.com/agent
cd "$SRC"
sha256sum -c SHA256SUMS >/dev/null || { echo "SHA256SUMS mismatch - nothing published"; exit 1; }
for f in AWMZA-Security-Setup.exe awmza-agent-macos-arm64 awmza-agent-macos-x86_64 awmza-agent-linux-x86_64 install.sh awmza-agent.py; do
  [ -s "$f" ] || { echo "missing $f"; exit 1; }
done
# the binaries must be built from the same source that is live
cmp -s awmza-agent.py "$DST/awmza-agent.py" || { echo "awmza-agent.py differs from the live one - stop"; exit 1; }
STAMP=$(date +%Y%m%d%H%M%S); BAK=/root/awmza-worklog/bak-agent-$STAMP; mkdir -p "$BAK"
cp -a "$DST"/. "$BAK"/
for f in AWMZA-Security-Setup.exe awmza-agent-macos-arm64 awmza-agent-macos-x86_64 awmza-agent-linux-x86_64 install.sh; do
  install -m 0644 -o root -g root "$f" "$DST/.$f.new" && mv -f "$DST/.$f.new" "$DST/$f"
done
grep -E 'AWMZA-Security-Setup.exe|awmza-agent-(macos|linux)|install.sh|awmza-agent.py' SHA256SUMS > "$DST/.SHA256SUMS.new"
mv -f "$DST/.SHA256SUMS.new" "$DST/SHA256SUMS"; chmod 644 "$DST/SHA256SUMS"
awk '$2=="AWMZA-Security-Setup.exe"{print $1"  AWMZA-Security-Setup.exe"}' SHA256SUMS > "$DST/AWMZA-Security-Setup.exe.sha256"
echo "published; old files in $BAK"; cat "$DST/SHA256SUMS"
