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

probe() {
  systemctl is-active --quiet xray || return 1
  curl -fsS --max-time "$PROBE_TIMEOUT" \
       --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
       -o /dev/null "$PROBE_URL"
}

if probe; then
  [ "$FAILS" -gt 0 ] && log notice "tunnel healthy again after $FAILS failed probe(s)"
  echo 0 > "$STATE/fails"
  echo up > "$STATE/tunnel"
  lifeline_off
  exit 0
fi

FAILS=$((FAILS + 1))
echo "$FAILS" > "$STATE/fails"
echo down > "$STATE/tunnel"
log warning "tunnel probe failed ($FAILS)"

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
