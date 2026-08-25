#!/bin/bash
# Refresh Xray geodata.
#
#   geoupdate.sh          update if the upstream release changed
#   geoupdate.sh --force  update regardless
#   geoupdate.sh --check  report versions, change nothing
#
# Two modes, chosen by config:
#   geodata.repo set, geodata.files empty  -> download every *.dat asset in the
#                                             latest release (new rule files
#                                             appear on their own)
#   geodata.files non-empty                -> exactly those, via url_template
#
# The installed release tag is recorded, so the daily timer is a cheap no-op
# until upstream actually publishes something.
set -euo pipefail

. /usr/local/lib/gateway/env
. /usr/local/lib/gateway/net.sh

DEST=/usr/local/share/xray
STAMP="$DEST/.release"
: "${GEO_MIN_BYTES:=102400}"

log() { printf '==> %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

MODE=${1:-}
INSTALLED=$(cat "$STAMP" 2>/dev/null || echo "none")

# Returns "tag<TAB>url<TAB>url..." for the latest release.
discover() {
  gw_curl --max-time 60 "https://api.github.com/repos/$GEO_REPO/releases/latest" \
    | python3 -c '
import json, sys
try:
    rel = json.load(sys.stdin)
except ValueError:
    sys.exit("could not parse the GitHub release response")
tag = rel.get("tag_name") or ""
urls = [a["browser_download_url"] for a in rel.get("assets", [])
        if a.get("name", "").endswith(".dat")]
if not tag or not urls:
    sys.exit("release has no tag or no .dat assets")
print("\t".join([tag] + urls))'
}

if [ -n "${GEO_FILES:-}" ]; then
  # Explicit file list: no release metadata, so there is nothing to compare.
  TAG="pinned:$GEO_FILES"
  URLS=""
  for name in $GEO_FILES; do
    URLS="$URLS$(printf '%s' "$GEO_URL_TEMPLATE" | sed "s|{0}|$name|g")"$'\n'
  done
else
  [ -n "${GEO_REPO:-}" ] || die "neither geodata.files nor geodata.repo is set"
  INFO=$(discover) || die "could not read the latest release of $GEO_REPO
  If this box has no direct internet yet, set bootstrap.socks_proxy."
  TAG=$(printf '%s' "$INFO" | cut -f1)
  URLS=$(printf '%s' "$INFO" | cut -f2- | tr '\t' '\n')
fi

COUNT=$(printf '%s' "$URLS" | grep -c . || true)

if [ "$MODE" = "--check" ]; then
  printf 'source    : %s\ninstalled : %s\nlatest    : %s\nfiles     : %s\n' \
    "${GEO_REPO:-$GEO_URL_TEMPLATE}" "$INSTALLED" "$TAG" "$COUNT"
  [ "$INSTALLED" = "$TAG" ] && echo "up to date" || echo "update available"
  exit 0
fi

if [ "$INSTALLED" = "$TAG" ] && [ "$MODE" != "--force" ]; then
  log "geodata already at $TAG"
  exit 0
fi

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
log "fetching $COUNT file(s) from $TAG"

while IFS= read -r url; do
  [ -z "$url" ] && continue
  name=$(basename "$url")
  gw_curl --max-time 300 -o "$TMP/$name" "$url" || die "download failed: $url"
  size=$(stat -c %s "$TMP/$name")
  # Catches truncated transfers and HTML error pages served with a 200.
  [ "$size" -ge "$GEO_MIN_BYTES" ] \
    || die "$name is only ${size}B (minimum ${GEO_MIN_BYTES}B) — aborting"
  printf '    %s (%sB)\n' "$name" "$size"
done <<< "$URLS"

install -d "$DEST"
BACKUP=$(mktemp -d)
for f in "$TMP"/*.dat; do
  name=$(basename "$f")
  [ -f "$DEST/$name" ] && cp -a "$DEST/$name" "$BACKUP/$name"
  install -m 0644 "$f" "$DEST/$name"
done

rollback() {
  for b in "$BACKUP"/*.dat; do
    [ -e "$b" ] && install -m 0644 "$b" "$DEST/$(basename "$b")"
  done
  rm -rf "$BACKUP"
}

# On first install there is no config and no service yet — fetching is the
# whole job at that point.
if [ -f /usr/local/etc/xray/config.json ]; then
  if ! xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1; then
    printf '[x] xray rejects the new geodata, rolling back\n' >&2
    rollback
    exit 1
  fi
fi
rm -rf "$BACKUP"

printf '%s' "$TAG" > "$STAMP"

if systemctl is-active --quiet xray 2>/dev/null; then
  systemctl restart xray
  logger -t gw-geoupdate "geodata updated to $TAG ($COUNT files), xray restarted"
else
  logger -t gw-geoupdate "geodata updated to $TAG ($COUNT files)"
fi
log "geodata now at $TAG"
ls -1 "$DEST"/*.dat 2>/dev/null | sed 's|.*/|    |'
