#!/bin/sh
# Policy routing for TPROXY. Marked packets are looked up in a table whose only
# route is `local default dev lo`, which makes the kernel deliver them to the
# transparent socket instead of forwarding them.
set -eu
. /usr/local/lib/gateway/env

case "${1:-up}" in
  up)
    ip rule list | grep -q "fwmark $(printf '0x%x' "$MARK_TPROXY") lookup $RT_TABLE" \
      || ip rule add fwmark "$MARK_TPROXY" lookup "$RT_TABLE" pref 100
    ip route replace local default dev lo table "$RT_TABLE"

    # rp_filter must be 0 on EVERY interface, not just the WAN one.
    #
    # The kernel validates the reverse path before delivering a TPROXY packet
    # locally, and that lookup runs with mark 0 — so it skips the fwmark rule
    # above and falls into whatever other policy rules exist. Tailscale
    # installs "from all lookup 52", which matches everything and can resolve a
    # LAN client via tailscale0 instead of the real interface. With rp_filter
    # on, that mismatch is a martian and the packet is dropped between
    # prerouting and the input chain, with no counter anywhere.
    #
    # The effective value is max(all, <iface>), so `all = 0` alone is not
    # enough, and interfaces created after sysctl ran (tailscale0) inherit
    # `default` from whenever they appeared. Setting every one of them is cheap
    # and idempotent.
    for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
      [ -w "$f" ] && echo 0 > "$f" 2>/dev/null || true
    done

    # Resolve the reverse path for LAN sources in the main table.
    #
    # Before delivering a TPROXY packet locally the kernel validates its
    # reverse path: it looks up a route back to the SOURCE, with mark 0. That
    # skips the fwmark rule above and falls into whatever else matches —
    # Tailscale installs "from all lookup 52" at priority 5270. If that table
    # answers with anything that is not a plain unicast route, validation
    # returns -EINVAL, the packet is treated as a martian, and it is dropped
    # between prerouting and the input chain with no counter anywhere.
    #
    # Sitting at priority 90, ahead of Tailscale's, this sends the reverse
    # lookup for our own LAN to the main table, where it resolves to the real
    # interface. It changes nothing about where traffic goes: main already
    # routes the LAN over that interface.
    ip rule list | grep -q "to $LAN_CIDR lookup main" \
      || ip rule add to "$LAN_CIDR" lookup main pref 90

    # Belt and braces: with rp_filter off, accept_local makes the kernel skip
    # that reverse lookup entirely rather than depend on how it resolves.
    for f in /proc/sys/net/ipv4/conf/*/accept_local; do
      [ -w "$f" ] && echo 1 > "$f" 2>/dev/null || true
    done
    ;;
  down)
    ip rule del fwmark "$MARK_TPROXY" lookup "$RT_TABLE" pref 100 2>/dev/null || true
    ip rule del to "$LAN_CIDR" lookup main pref 90 2>/dev/null || true
    ip route flush table "$RT_TABLE" 2>/dev/null || true
    ;;
  status)
    ip rule list | grep -E "lookup $RT_TABLE" || echo "no fwmark rule"
    ip route show table "$RT_TABLE" || true
    ;;
  *)
    echo "usage: $0 {up|down|status}" >&2; exit 2 ;;
esac
