#!/bin/sh
# Refresh Xray geodata. Validates before swapping: a truncated geoip.dat takes
# the tunnel down, and this runs unattended.
set -eu
. /usr/local/lib/gateway/env
DEST=/usr/local/share/xray
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

fetch() {
  curl -fsSL --max-time 120 -o "$TMP/$2" "$1"
}

# Iran-focused rules, which is what makes the domestic-direct split useful.
BASE=https://github.com/chocolate4u/Iran-v2ray-rules/releases/latest/download
fetch "$BASE/geoip.dat"   geoip.dat
fetch "$BASE/geosite.dat" geosite.dat

for f in geoip.dat geosite.dat; do
  [ -s "$TMP/$f" ] || { echo "$f empty, aborting" >&2; exit 1; }
  # 100 KB floor: catches truncated downloads and HTML error pages
  [ "$(stat -c %s "$TMP/$f")" -gt 102400 ] || { echo "$f too small, aborting" >&2; exit 1; }
done

install -d "$DEST"
for f in geoip.dat geosite.dat; do
  [ -f "$DEST/$f" ] && cp -a "$DEST/$f" "$DEST/$f.bak"
  install -m 0644 "$TMP/$f" "$DEST/$f"
done

# On first install there is no config and no service yet — fetching the data is
# the whole job at that point.
if [ -f /usr/local/etc/xray/config.json ]; then
  if ! xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
    echo "xray rejects the new geodata, rolling back" >&2
    for f in geoip.dat geosite.dat; do
      [ -f "$DEST/$f.bak" ] && mv "$DEST/$f.bak" "$DEST/$f"
    done
    exit 1
  fi
fi

if systemctl is-active --quiet xray; then
  systemctl restart xray
  logger -t gw-geoupdate "geodata updated, xray restarted"
else
  logger -t gw-geoupdate "geodata updated (xray not running yet)"
fi
