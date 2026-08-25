#!/bin/sh
# Refresh Xray geodata from the configured source.
#
# Validates before swapping: a truncated geoip.dat takes the tunnel down, and
# this runs unattended from a timer.
set -eu
. /usr/local/lib/gateway/env
. /usr/local/lib/gateway/net.sh

DEST=/usr/local/share/xray
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

: "${GEO_URL_TEMPLATE:?geodata.url_template is not set — run 'gw apply'}"
: "${GEO_FILES:=geoip geosite}"
: "${GEO_MIN_BYTES:=102400}"

for name in $GEO_FILES; do
  url=$(printf '%s' "$GEO_URL_TEMPLATE" | sed "s|{0}|$name|g")
  echo "fetching $name.dat from $url"
  gw_curl --max-time 180 -o "$TMP/$name.dat" "$url" \
    || { echo "download failed: $url" >&2; exit 1; }

  size=$(stat -c %s "$TMP/$name.dat")
  # Catches truncated transfers and HTML error pages served with a 200.
  if [ "$size" -lt "$GEO_MIN_BYTES" ]; then
    echo "$name.dat is only ${size}B (minimum ${GEO_MIN_BYTES}B) — aborting" >&2
    exit 1
  fi
done

install -d "$DEST"
for name in $GEO_FILES; do
  [ -f "$DEST/$name.dat" ] && cp -a "$DEST/$name.dat" "$DEST/$name.dat.bak"
  install -m 0644 "$TMP/$name.dat" "$DEST/$name.dat"
done

# On first install there is no config and no service yet — fetching the data is
# the whole job at that point.
if [ -f /usr/local/etc/xray/config.json ]; then
  if ! xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
    echo "xray rejects the new geodata, rolling back" >&2
    for name in $GEO_FILES; do
      [ -f "$DEST/$name.dat.bak" ] && mv "$DEST/$name.dat.bak" "$DEST/$name.dat"
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
echo "geodata updated: $GEO_FILES"
