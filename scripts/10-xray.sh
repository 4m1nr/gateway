#!/usr/bin/env bash
# Install and pin Xray, then bring up the tunnel — SOCKS only at this stage.
# Interception comes later, so a broken tunnel here cannot take the LAN down.
source "$(dirname "$0")/../lib/common.sh"
need_root

VER=$(version_of xray)
SHA=$(sha_of xray)
[ -n "$VER" ] || die "no xray version pinned in versions.toml"

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ASSET=Xray-linux-64.zip ;;
  aarch64) ASSET=Xray-linux-arm64-v8a.zip ;;
  i686|i386) ASSET=Xray-linux-32.zip ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
URL="https://github.com/XTLS/Xray-core/releases/download/$VER/$ASSET"

info "downloading Xray $VER ($ASSET)"
curl -fsSL --max-time 300 -o "$TMP/$ASSET" "$URL" || die "download failed: $URL"
verify_sha "$TMP/$ASSET" "$SHA" "$URL.dgst"

unzip -q -o "$TMP/$ASSET" -d "$TMP/x"
install -m 0755 "$TMP/x/xray" /usr/local/bin/xray
install -d /usr/local/share/xray /usr/local/etc/xray
for f in geoip.dat geosite.dat; do
  [ -f "$TMP/x/$f" ] && install -m 0644 "$TMP/x/$f" /usr/local/share/xray/$f
done
info "installed $(/usr/local/bin/xray version | head -1)"

id xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray

info "generating configs"
"$REPO/bin/gw" render >/dev/null

install -D -m 0644 "$REPO/build/usr/local/lib/gateway/env" /usr/local/lib/gateway/env
for s in geoupdate.sh ip-rules.sh ts-bypass.sh; do
  [ -f "$REPO/build/usr/local/lib/gateway/$s" ] \
    && install -D -m 0755 "$REPO/build/usr/local/lib/gateway/$s" "/usr/local/lib/gateway/$s"
done

info "fetching Iran-focused geodata (this is what makes the domestic split useful)"
/usr/local/lib/gateway/geoupdate.sh || warn "geodata fetch failed — the bundled geoip/geosite from the release will be used instead"

info "staging the Xray config"
install -D -m 0644 "$REPO/build/usr/local/etc/xray/config.json" \
  /usr/local/etc/xray/config.json
chown -R xray:xray /usr/local/etc/xray

install -D -m 0644 "$REPO/build/etc/systemd/system/xray.service" \
  /etc/systemd/system/xray.service
install -D -m 0644 "$REPO/build/etc/systemd/system/gw-network.service" \
  /etc/systemd/system/gw-network.service
install -D -m 0644 "$REPO/build/etc/nftables.d/gateway.nft" /etc/nftables.d/gateway.nft

/usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json \
  || die "Xray rejected the generated config"

systemctl daemon-reload
systemctl enable --now gw-network.service
systemctl enable --now xray

sleep 2
SOCKS=$(sed -n 's/^SOCKS_PORT=//p' /usr/local/lib/gateway/env)
info "testing the tunnel through SOCKS (nothing is intercepted yet)"
if OUT=$(curl -fsS --max-time 15 --socks5-hostname "127.0.0.1:$SOCKS" https://api.ipify.org 2>&1); then
  info "tunnel is up — exit IP: $OUT"
else
  warn "tunnel probe failed: $OUT"
  warn "Check, in this order: the clock (date -u), the XHTTP params against the"
  warn "server (path/host/mode/ALPN), and 'journalctl -u xray -n 50'."
  exit 1
fi

echo
echo "Next: sudo scripts/20-adguard.sh"
