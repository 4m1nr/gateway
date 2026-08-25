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
    ;;
  down)
    ip rule del fwmark "$MARK_TPROXY" lookup "$RT_TABLE" pref 100 2>/dev/null || true
    ip route flush table "$RT_TABLE" 2>/dev/null || true
    ;;
  status)
    ip rule list | grep -E "lookup $RT_TABLE" || echo "no fwmark rule"
    ip route show table "$RT_TABLE" || true
    ;;
  *)
    echo "usage: $0 {up|down|status}" >&2; exit 2 ;;
esac
