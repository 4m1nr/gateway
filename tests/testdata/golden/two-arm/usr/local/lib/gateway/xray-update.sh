#!/bin/bash
# Install or update Xray-core.
#
#   xray-update.sh            install/update to the version pinned in versions.toml
#   xray-update.sh latest     resolve the newest GitHub release and use that
#   xray-update.sh v25.9.11   a specific version
#   xray-update.sh --check    report what is installed vs available, change nothing
#
# The new binary is tested against the LIVE config before it replaces the old
# one, and the old one is kept so a failed restart rolls straight back. An
# update that breaks the tunnel would otherwise take the whole LAN offline with
# no easy way back in.
set -euo pipefail

GW_LIB="${GW_LIB:-/usr/local/lib/gateway}"
. "$GW_LIB/env"
. "$GW_LIB/net.sh"

# Paths are overridable so the update path can be exercised against a scratch
# tree rather than the live system. Nothing here changes on a real box: these
# are the same locations, just not hardcoded, and the download-verify-test-
# rollback sequence is the part most worth being able to test.
BIN="${GW_XRAY_BIN:-/usr/local/bin/xray}"
SHARE="${GW_XRAY_SHARE:-/usr/local/share/xray}"
CONFIG="${GW_XRAY_CONFIG:-/usr/local/etc/xray/config.json}"
REPO_URL=https://github.com/XTLS/Xray-core

log() { printf '==> %s\n' "$*"; }
die() { printf '[x] %s\n' "$*" >&2; exit 1; }

installed_version() {
  [ -x "$BIN" ] || { echo "none"; return; }
  "$BIN" version 2>/dev/null | head -1 | grep -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 \
    | sed 's/^v*/v/'
}

latest_version() {
  # The /releases/latest redirect avoids the API rate limit entirely.
  gw_curl --max-time 30 -o /dev/null -w '%{url_effective}' \
    "$REPO_URL/releases/latest" 2>/dev/null \
    | sed 's|.*/tag/||'
}

pinned_version() {
  sed -n '/^\[xray\]/,/^\[/p' "${REPO:-/opt/gateway}/versions.toml" 2>/dev/null \
    | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1
}

asset_for_arch() {
  case "$(uname -m)" in
    x86_64)    echo Xray-linux-64.zip ;;
    aarch64)   echo Xray-linux-arm64-v8a.zip ;;
    armv7l)    echo Xray-linux-arm32-v7a.zip ;;
    i686|i386) echo Xray-linux-32.zip ;;
    *) die "unsupported architecture: $(uname -m)" ;;
  esac
}

CURRENT=$(installed_version)

if [ "${1:-}" = "--check" ]; then
  LATEST=$(latest_version || echo "unknown")
  printf 'installed : %s\npinned    : %s\nlatest    : %s\n' \
    "$CURRENT" "$(pinned_version)" "$LATEST"
  if [ "$CURRENT" = "$LATEST" ]; then
    echo "up to date"
  elif [ "$LATEST" = "unknown" ] || [ -z "$LATEST" ]; then
    echo "could not reach GitHub — set bootstrap.socks_proxy if this box has no direct access yet"
    exit 1
  else
    echo "update available: $CURRENT -> $LATEST"
  fi
  exit 0
fi

WANT="${1:-}"
[ -z "$WANT" ] && WANT=$(pinned_version)
[ "$WANT" = "latest" ] && WANT=$(latest_version)
[ -n "$WANT" ] || die "could not determine which version to install"
case "$WANT" in v*) ;; *) WANT="v$WANT" ;; esac

if [ "$CURRENT" = "$WANT" ] && [ "${FORCE:-0}" != "1" ]; then
  log "Xray $CURRENT is already installed"
  exit 0
fi

ASSET=$(asset_for_arch)
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL="$REPO_URL/releases/download/$WANT/$ASSET"

log "downloading Xray $WANT ($ASSET)"
gw_curl --max-time 300 -o "$TMP/$ASSET" "$URL" || die "download failed: $URL"

# The digest comes from the same host as the download, so it proves the file is
# intact, not that it is authentic. Pin a sha256 in versions.toml for that.
EXPECT=$(sed -n '/^\[xray\]/,/^\[/p' "${REPO:-/opt/gateway}/versions.toml" 2>/dev/null \
         | sed -n 's/^sha256 *= *"\(.*\)"/\1/p' | head -1)
ACTUAL=$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)
if [ -n "$EXPECT" ]; then
  [ "$ACTUAL" = "$EXPECT" ] || die "checksum mismatch
  expected $EXPECT
  got      $ACTUAL"
  log "checksum verified against the pin in versions.toml"
elif gw_curl --max-time 30 -o "$TMP/dgst" "$URL.dgst" 2>/dev/null; then
  grep -qi "$ACTUAL" "$TMP/dgst" || die "published digest does not match the download"
  log "checksum matches the published digest (integrity only, not authenticity)"
else
  printf '[!] no checksum available — proceeding unverified\n' >&2
fi

unzip -q -o "$TMP/$ASSET" -d "$TMP/x"
[ -x "$TMP/x/xray" ] || chmod +x "$TMP/x/xray"

NEW_VERSION=$("$TMP/x/xray" version | head -1)
log "downloaded: $NEW_VERSION"

# Test the NEW binary against the LIVE config before it goes anywhere near
# /usr/local/bin. A config the new version rejects would otherwise be found out
# only when the service failed to come back.
if [ -f "$CONFIG" ]; then
  install -d "$SHARE"
  for f in geoip.dat geosite.dat; do
    [ -f "$TMP/x/$f" ] && [ ! -f "$SHARE/$f" ] && install -m 0644 "$TMP/x/$f" "$SHARE/$f"
  done
  XRAY_LOCATION_ASSET="$SHARE" "$TMP/x/xray" run -test -config "$CONFIG" >/dev/null \
    || die "Xray $WANT rejects the current config — not installing.
  Check the release notes for a breaking change, then adjust the outbound JSON."
  log "the new binary accepts the current config"
fi

if [ -x "$BIN" ]; then
  cp -a "$BIN" "$BIN.previous"
  log "kept the previous binary at $BIN.previous"
fi
install -m 0755 "$TMP/x/xray" "$BIN"

# Only seed geodata if there is none; `gw agent geoupdate` owns it after that.
install -d "$SHARE"
for f in geoip.dat geosite.dat; do
  [ -f "$TMP/x/$f" ] && [ ! -f "$SHARE/$f" ] && install -m 0644 "$TMP/x/$f" "$SHARE/$f"
done

if systemctl is-active --quiet xray 2>/dev/null; then
  log "restarting xray"
  if ! systemctl restart xray; then
    printf '[x] xray failed to start on %s — rolling back\n' "$WANT" >&2
    [ -x "$BIN.previous" ] && install -m 0755 "$BIN.previous" "$BIN"
    systemctl restart xray || true
    exit 1
  fi
  sleep 3
  if ! systemctl is-active --quiet xray; then
    printf '[x] xray did not stay up on %s — rolling back\n' "$WANT" >&2
    [ -x "$BIN.previous" ] && install -m 0755 "$BIN.previous" "$BIN"
    systemctl restart xray || true
    exit 1
  fi
fi

log "Xray is now $("$BIN" version | head -1)"
printf '\nPin it so rebuilds are reproducible:\n  versions.toml -> [xray] version = "%s"\n' "$WANT"
