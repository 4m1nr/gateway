#!/bin/bash
# Tunnel watchdog. Escalates: probe -> restart Xray -> (balancer handles
# failover) -> engage the Tailscale lifeline so remote admin survives.
#
# It never opens a direct path for client traffic. A broken tunnel stays
# fail-closed; the only thing the lifeline frees is tailscaled itself.
set -uo pipefail
. /usr/local/lib/gateway/env

STATE=/run/gateway
mkdir -p "$STATE"
FAILS=$(cat "$STATE/fails" 2>/dev/null || echo 0)
LIFELINE=$(cat "$STATE/lifeline" 2>/dev/null || echo 0)

log() { logger -t gw-health -p "daemon.$1" "$2"; }

lifeline_on() {
  # Restart tailscaled FIRST, then add the rule: the cgroup ID nftables
  # resolves at insertion time is invalidated by the restart. Re-applied every
  # cycle while engaged, so an unrelated tailscaled restart self-heals.
  if [ "$LIFELINE" != "1" ]; then
    systemctl try-restart tailscaled >/dev/null 2>&1
    sleep 2
  fi
  if /usr/local/lib/gateway/ts-bypass.sh lifeline on 2>/dev/null; then
    if [ "$LIFELINE" != "1" ]; then
      echo 1 > "$STATE/lifeline"
      log err "tunnel down ${LIFELINE_MIN}m+ — Tailscale lifeline ENGAGED (tailscaled now direct). Client traffic stays fail-closed."
    fi
  else
    # Deliberately no broader fallback rule. Anything wide enough to work
    # without cgroup matching (say, all root traffic to :443) would also free
    # AdGuard's DoH and every other root process on the box.
    log err "tunnel down ${LIFELINE_MIN}m+ but the tailscaled cgroup rule could not be added — lifeline NOT engaged. Recover from the console."
  fi
}

lifeline_off() {
  [ "$LIFELINE" = "1" ] || return 0
  /usr/local/lib/gateway/ts-bypass.sh lifeline off
  echo 0 > "$STATE/lifeline"
  systemctl try-restart tailscaled >/dev/null 2>&1
  log notice "tunnel recovered — Tailscale lifeline released"
}

# The probe that matters: a plain request, which the output chain marks and
# policy routing loops back through lo into the TPROXY listener. That exercises
# the whole path a client's traffic takes — marking, policy routing,
# prerouting interception, Xray, the tunnel.
#
# The old probe used --socks5-hostname to reach Xray's SOCKS inbound directly.
# That skips every one of those steps, so it reported "tunnel UP" through two
# separate outages where the box had no internet at all: once when prerouting
# returned early on lo, and once when a poisoned DNS answer sent traffic out
# unintercepted. A health check that cannot see the failure is worse than none,
# because it argues against you while you debug.
probe_intercepted() {
  # Deliberately not proxied: a proxy would bypass the path being tested.
  curl -fsS --max-time "$PROBE_TIMEOUT" -o /dev/null "$PROBE_URL"  # gw:direct-ok
}

# Kept only to tell the two failures apart: if this works and the one above
# does not, Xray and the tunnel are fine and interception is broken.
probe_socks() {
  curl -fsS --max-time "$PROBE_TIMEOUT" \
       --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
       -o /dev/null "$PROBE_URL"
}

if ! systemctl is-active --quiet xray; then
  STATUS=down
  DETAIL="xray is not running"
elif probe_intercepted; then
  STATUS=up
  DETAIL=""
elif probe_socks; then
  # Xray and the tunnel are healthy; the packets are not reaching them.
  STATUS=degraded
  DETAIL="the tunnel works via SOCKS but intercepted traffic does not reach it — check the nftables prerouting/output chains and 'ip rule'"
else
  STATUS=down
  DETAIL="neither the intercepted path nor SOCKS reached $PROBE_URL"
fi

echo "$STATUS" > "$STATE/tunnel"
[ -n "$DETAIL" ] && echo "$DETAIL" > "$STATE/detail" || rm -f "$STATE/detail"

if [ "$STATUS" = up ]; then
  [ "$FAILS" -gt 0 ] && log notice "gateway healthy again after $FAILS failed probe(s)"
  echo 0 > "$STATE/fails"
  lifeline_off
  exit 0
fi

FAILS=$((FAILS + 1))
echo "$FAILS" > "$STATE/fails"
if [ "$STATUS" = degraded ]; then
  log err "INTERCEPTION BROKEN ($FAILS): $DETAIL"
else
  log warning "gateway probe failed ($FAILS): $DETAIL"
fi

if [ "$FAILS" -eq "$RESTART_AFTER" ]; then
  log err "restarting xray after $FAILS failed probes"
  systemctl restart xray
fi

if [ "$FAILS" -eq "$FALLBACK_AFTER" ]; then
  log err "still down after $FAILS probes — check the server, the XHTTP params, and the clock ($(date -u +%FT%TZ))"
fi

if [ "$LIFELINE_MIN" -gt 0 ]; then
  DOWN_SEC=$((FAILS * INTERVAL))
  [ "$DOWN_SEC" -ge $((LIFELINE_MIN * 60)) ] && lifeline_on
fi
exit 0
