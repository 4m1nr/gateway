#!/bin/bash
# Install or update AdGuard Home.
#
#   adguard-update.sh            update to the pinned version
#   adguard-update.sh latest     newest GitHub release
#   adguard-update.sh v0.107.68  a specific version
#   adguard-update.sh --check    report versions, change nothing
#
# Same shape as xray-update.sh: verify, keep the old binary, roll back if the
# service does not come up. AdGuard is less critical than the tunnel — a failed
# update costs the LAN its DNS, not its internet — but the recovery path should
# not be "SSH in and figure out what happened" either.
set -euo pipefail

. /usr/local/lib/gateway/env
. /usr/local/lib/gateway/net.sh

DIR=/opt/AdGuardHome
BIN="$DIR/AdGuardHome"
CONF="$DIR/AdGuardHome.yaml"
REPO_URL=https://github.com/AdguardTeam/AdGuardHome

log() { printf '==> %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

installed_version() {
  [ -x "$BIN" ] || { echo none; return; }
  "$BIN" --version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
    || echo unknown
}

latest_version() {
  gw_curl -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest" 2>/dev/null \
    | sed 's|.*/tag/||'
}

pinned_version() {
  sed -n '/^\[adguard\]/,/^\[/p' "${REPO:-/opt/gateway}/versions.toml" 2>/dev/null \
    | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1
}

asset_for_arch() {
  case "$(uname -m)" in
    x86_64)    echo AdGuardHome_linux_amd64.tar.gz ;;
    aarch64)   echo AdGuardHome_linux_arm64.tar.gz ;;
    armv7l)    echo AdGuardHome_linux_armv7.tar.gz ;;
    i686|i386) echo AdGuardHome_linux_386.tar.gz ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

CURRENT=$(installed_version)

if [ "${1:-}" = "--check" ]; then
  LATEST=$(latest_version || echo unknown)
  printf 'installed : %s\npinned    : %s\nlatest    : %s\n' \
    "$CURRENT" "$(pinned_version)" "$LATEST"
  [ "$CURRENT" = "$LATEST" ] && echo "up to date" || echo "update available"
  exit 0
fi

WANT="${1:-}"
[ -z "$WANT" ] && WANT=$(pinned_version)
[ "$WANT" = "latest" ] && WANT=$(latest_version)
[ -n "$WANT" ] || die "could not determine which version to install"

if [ "$CURRENT" = "$WANT" ] && [ "${FORCE:-0}" != "1" ]; then
  log "AdGuard Home $CURRENT is already installed"
  exit 0
fi

ASSET=$(asset_for_arch)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL="$REPO_URL/releases/download/$WANT/$ASSET"

log "downloading AdGuard Home $WANT ($ASSET)"
gw_curl --max-time 300 -o "$TMP/$ASSET" "$URL" || die "download failed: $URL"

ACTUAL=$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)
EXPECT=$(sed -n '/^\[adguard\]/,/^\[/p' "${REPO:-/opt/gateway}/versions.toml" 2>/dev/null \
         | sed -n 's/^sha256 *= *"\(.*\)"/\1/p' | head -1)
if [ -n "$EXPECT" ]; then
  [ "$ACTUAL" = "$EXPECT" ] || die "checksum mismatch
  expected $EXPECT
  got      $ACTUAL"
  log "checksum verified against the pin in versions.toml"
elif gw_curl --max-time 30 -o "$TMP/sums" "$REPO_URL/releases/download/$WANT/checksums.txt" 2>/dev/null; then
  grep -q "$ACTUAL" "$TMP/sums" || die "published checksum does not match the download"
  log "checksum matches the published list (integrity only, not authenticity)"
else
  printf '[!] no checksum available — proceeding unverified\n' >&2
fi

tar -xzf "$TMP/$ASSET" -C "$TMP"
NEW="$TMP/AdGuardHome/AdGuardHome"
[ -x "$NEW" ] || die "the archive did not contain an AdGuardHome binary"

# The config is schema-migrated by AdGuard itself, so the useful pre-flight is
# "does the new binary accept the current file" rather than a dry run.
if [ -f "$CONF" ] && "$NEW" --help 2>&1 | grep -q -- --check-config; then
  "$NEW" --check-config -c "$CONF" >/dev/null 2>&1 \
    || die "AdGuard Home $WANT rejects the current config — not installing"
  log "the new binary accepts the current config"
fi

WAS_ACTIVE=0
systemctl is-active --quiet AdGuardHome 2>/dev/null && WAS_ACTIVE=1
[ "$WAS_ACTIVE" = 1 ] && systemctl stop AdGuardHome

[ -x "$BIN" ] && cp -a "$BIN" "$BIN.previous" && log "kept the previous binary at $BIN.previous"
install -d "$DIR"
install -m 0755 "$NEW" "$BIN"

if [ "$WAS_ACTIVE" = 1 ]; then
  if ! systemctl start AdGuardHome || ! sleep 3 || ! systemctl is-active --quiet AdGuardHome; then
    printf '[x] AdGuard Home did not come back on %s — rolling back\n' "$WANT" >&2
    [ -x "$BIN.previous" ] && install -m 0755 "$BIN.previous" "$BIN"
    systemctl start AdGuardHome || true
    exit 1
  fi
fi

log "AdGuard Home is now $(installed_version)"
printf '\nPin it so rebuilds are reproducible:\n  versions.toml -> [adguard] version = "%s"\n' "$WANT"
