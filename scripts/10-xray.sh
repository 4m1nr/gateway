#!/usr/bin/env bash
# Install and pin Xray, then bring up the tunnel — SOCKS only at this stage.
# Interception comes later, so a broken tunnel here cannot take the LAN down.
source "$(dirname "$0")/../lib/common.sh"
need_root

info "generating configs"
"$REPO/bin/gw" render >/dev/null

install -D -m 0644 "$REPO/build/usr/local/lib/gateway/env" /usr/local/lib/gateway/env
for s in net.sh geoupdate.sh ip-rules.sh ts-bypass.sh xray-update.sh; do
  [ -f "$REPO/build/usr/local/lib/gateway/$s" ] \
    && install -D -m 0755 "$REPO/build/usr/local/lib/gateway/$s" "/usr/local/lib/gateway/$s"
done

id xray >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin xray

# Same installer `gw update xray` uses: verify, test against the live config,
# roll back if the service does not come up.
info "installing Xray"
GW_PROXY="${GW_PROXY:-$(gw_proxy)}" REPO="$REPO" \
  /usr/local/lib/gateway/xray-update.sh "$(version_of xray)"

info "fetching geodata (this is what makes the domestic split useful)"
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
SOCKS=$( . /usr/local/lib/gateway/env; printf '%s' "$SOCKS_PORT" )
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
