#!/usr/bin/env bash
# AdGuard Home as the LAN resolver. Its own upstream traffic is captured by the
# OUTPUT chain like any other local process, so DoH already rides the tunnel.
# Resolve $0 through symlinks before locating the shared helpers — a
# symlinked script would otherwise look for lib/common.sh next to the
# symlink instead of next to the real file.
_self="$0"
while [ -L "$_self" ]; do
  _link="$(readlink "$_self")"
  case "$_link" in /*) _self="$_link" ;; *) _self="$(dirname "$_self")/$_link" ;; esac
done
source "$(dirname "$_self")/../lib/common.sh"
need_root

VER=$(version_of adguard)
SHA=$(sha_of adguard)
ARCH=$(uname -m)
case "$ARCH" in
  x86_64)  ASSET=AdGuardHome_linux_amd64.tar.gz ;;
  aarch64) ASSET=AdGuardHome_linux_arm64.tar.gz ;;
  i686|i386) ASSET=AdGuardHome_linux_386.tar.gz ;;
  *) die "unsupported architecture: $ARCH" ;;
esac

# Port 53 has to be free before AdGuard can bind it.
if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
  info "disabling the systemd-resolved stub listener (it owns :53)"
  install -d /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/99-gateway.conf <<'CONF'
[Resolve]
DNSStubListener=no
CONF
  systemctl disable --now systemd-resolved
fi

"$REPO/bin/gw" render >/dev/null
install -D -m 0644 "$REPO/build/usr/local/lib/gateway/env" /usr/local/lib/gateway/env

if [ ! -x /opt/AdGuardHome/AdGuardHome ]; then
  # Same installer `gw update adguard` uses: verify, keep the old binary,
  # roll back if the service does not come up.
  install -D -m 0755 "$REPO/build/usr/local/lib/gateway/adguard-update.sh" \
    /usr/local/lib/gateway/adguard-update.sh
  install -D -m 0755 "$REPO/build/usr/local/lib/gateway/net.sh" \
    /usr/local/lib/gateway/net.sh
  GW_PROXY="${GW_PROXY:-$(gw_proxy)}" REPO="$REPO" \
    /usr/local/lib/gateway/adguard-update.sh "$(version_of adguard)"
  /opt/AdGuardHome/AdGuardHome -s install
else
  info "AdGuard Home already installed"
fi

eval "$( . /usr/local/lib/gateway/env; printf 'UI_PORT=%s\nBOX=%s\n' "$UI_PORT" "$BOX_IP" )"

if [ ! -f /opt/AdGuardHome/AdGuardHome.yaml ]; then
  cat <<NEXT

AdGuard Home is installed but not yet configured.

  1. Open http://$BOX:$UI_PORT from a machine on the LAN.
  2. Complete the setup wizard. Set an admin password — this is the one thing
     gw does not manage, deliberately: a password hash does not belong in a
     git repo.
  3. Listen interface: All interfaces, port 53. The firewall is what restricts
     who can reach it.
  4. Come back and run: sudo gw apply

`gw apply` will then take over upstreams, filters, per-client profiles and
retention from gateway.toml, and leave your password and everything else alone.
NEXT
  exit 0
fi

info "merging gateway settings into AdGuard Home"
python3 "$REPO/lib/agh_merge.py" /opt/AdGuardHome/AdGuardHome.yaml \
  "$REPO/build/adguard-overrides.json"
systemctl restart AdGuardHome
sleep 2

info "pointing this box at its own resolver"
chattr -i /etc/resolv.conf 2>/dev/null || true
printf '# Managed by gw — this box resolves through its own AdGuard instance\nnameserver 127.0.0.1\noptions edns0\n' > /etc/resolv.conf

if getent hosts example.com >/dev/null 2>&1; then
  info "local resolution works"
else
  warn "local resolution failed — check 'journalctl -u AdGuardHome -n 30'"
fi

echo
echo "Next: sudo scripts/30-tailscale.sh"
