#!/usr/bin/env bash
# Base system: packages, clock, logging, and the switch to systemd-networkd.
#
# Run this from the console, or at least be ready to reconnect: it takes over
# network configuration, which will briefly drop an SSH session.
source "$(dirname "$0")/../lib/common.sh"
need_root

info "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  nftables iproute2 curl ca-certificates unzip jq \
  chrony python3 python3-yaml \
  ethtool tcpdump dnsutils mtr-tiny vnstat \
  zram-tools unattended-upgrades

TZ=$(sed -n 's/^timezone *= *"\(.*\)"/\1/p' "$CONFIG" | head -1)
if [ -n "$TZ" ]; then
  info "timezone -> $TZ"
  timedatectl set-timezone "$TZ"
fi

# TLS and REALITY both fail on a skewed clock, and NTP is pinned to a direct
# path in the firewall precisely so this can never depend on the tunnel.
info "enabling chrony"
systemctl enable --now chrony
chronyc makestep >/dev/null 2>&1 || true
# chrony-wait holds time-sync.target until the clock is actually synced, which
# is what xray.service orders itself after. Thin clients often have a flat CMOS
# battery and boot years out of date; without this the tunnel fails at every
# boot until chrony catches up.
systemctl enable chrony-wait.service 2>/dev/null \
  || warn "chrony-wait.service unavailable — Xray may start before the clock is correct"

info "capping the journal (thin-client flash is small and slow)"
JMAX=$(sed -n 's/^journal_max_use *= *"\(.*\)"/\1/p' "$CONFIG" | head -1)
install -d /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/99-gateway.conf <<CONF
[Journal]
SystemMaxUse=${JMAX:-200M}
RuntimeMaxUse=64M
CONF
systemctl restart systemd-journald

if grep -q '^zram *= *true' "$CONFIG"; then
  info "enabling zram"
  systemctl enable --now zramswap 2>/dev/null || warn "zramswap unavailable, skipping"
fi

# --- the risky part -------------------------------------------------------
WAN=$(sed -n 's/^wan_if *= *"\(.*\)"/\1/p' "$CONFIG" | head -1)
info "switching network management to systemd-networkd on $WAN"
warn "This replaces the current network configuration. If you are on SSH over"
warn "$WAN, the connection will drop and come back on the static address."
confirm "continue?"

# Keep name resolution alive until AdGuard takes over in 20-adguard.sh.
ROUTER=$(sed -n 's/^router *= *"\(.*\)"/\1/p' "$CONFIG" | head -1)
if [ ! -L /etc/resolv.conf ]; then
  printf 'nameserver %s\n' "${ROUTER:-1.1.1.1}" > /etc/resolv.conf
fi

systemctl disable --now NetworkManager 2>/dev/null || true
if systemctl is-enabled networking >/dev/null 2>&1; then
  warn "disabling ifupdown (/etc/network/interfaces)"
  systemctl disable networking 2>/dev/null || true
fi
systemctl enable systemd-networkd systemd-networkd-wait-online

info "staging the gateway configuration"
"$REPO/bin/gw" render

install -D -m 0644 "$REPO/build/etc/systemd/network/10-gateway-wan.network" \
  /etc/systemd/network/10-gateway-wan.network
install -D -m 0644 "$REPO/build/etc/sysctl.d/99-gateway.conf" \
  /etc/sysctl.d/99-gateway.conf
sysctl --system >/dev/null

systemctl restart systemd-networkd
sleep 3

info "checking connectivity"
if ping -c2 -W3 "$ROUTER" >/dev/null 2>&1; then
  info "router $ROUTER reachable"
else
  die "cannot reach the router at $ROUTER — check net.static_ip and net.wan_if in $CONFIG"
fi

cat <<'NEXT'

Base system ready. Before proxying anything, confirm plain forwarding works:

  1. On another device, set its gateway to this box's static IP.
  2. sudo nft -f - <<'RULE'
     table ip tmpnat { chain post { type nat hook postrouting priority srcnat; masquerade } }
RULE
  3. Browse from that device. It should work, unproxied.
  4. sudo nft delete table ip tmpnat

Then: sudo scripts/10-xray.sh
NEXT
