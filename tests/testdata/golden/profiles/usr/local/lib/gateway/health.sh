#!/bin/bash
# Tunnel watchdog. Escalates: probe -> restart Xray -> (balancer handles
# failover) -> engage the Tailscale lifeline so remote admin survives.
#
# It never opens a direct path for client traffic. A broken tunnel stays
# fail-closed; the only thing the lifeline frees is tailscaled itself.
set -uo pipefail
# Overridable for the same reason xray-update.sh takes them: this escalates to
# restarting Xray and rewriting nftables, and none of that can be exercised
# against paths only root on the real box can write.
GW_LIB="${GW_LIB:-/usr/local/lib/gateway}"
. "$GW_LIB/env"

STATE="${GW_STATE:-/run/gateway}"
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
  if "$GW_LIB/ts-bypass.sh" lifeline on 2>/dev/null; then
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
  "$GW_LIB/ts-bypass.sh" lifeline off
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
#
# Two attempts, not one. The failure path from here restarts Xray, and a
# restart drops every live connection on every client — so the bar for calling
# a probe failed has to be higher than one timeout. One lost packet, or a
# probe that queued behind a client saturating a 40 Mb line, is not an outage;
# treating it as one turns the watchdog into the fault it is meant to catch.
probe_intercepted() {
  # Deliberately not proxied: a proxy would bypass the path being tested.
  curl -fsS --max-time "$PROBE_TIMEOUT" -o /dev/null "$PROBE_URL" && return 0  # gw:direct-ok
  sleep 2
  curl -fsS --max-time "$PROBE_TIMEOUT" -o /dev/null "$PROBE_URL"  # gw:direct-ok
}

# Kept only to tell the two failures apart: if this works and the one above
# does not, Xray and the tunnel are fine and interception is broken.
probe_socks() {
  curl -fsS --max-time "$PROBE_TIMEOUT" \
       --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
       -o /dev/null "$PROBE_URL"
}

# Bytes the tunnel has actually received, cumulative, from Xray's stats API.
# Downlink only, and only from outbounds that are not direct/block: bytes
# arriving from the server are proof the tunnel works, where uplink is only
# proof that something wrote into a socket that may be dead.
tunnel_downlink() {
  local out
  out=$(xray api statsquery --server="127.0.0.1:${API_PORT:-10085}" 2>/dev/null) || return 1
  printf '%s' "$out" | awk -F'"' '
    /"name"/  { n = $4 }
    /"value"/ { if (n ~ /^outbound/ && n ~ /downlink/ &&
                    n !~ />>>direct>>>/ && n !~ />>>block>>>/) s += $4 }
    END { print s + 0 }'
}

BYTES_PREV=$(cat "$STATE/bytes" 2>/dev/null || echo 0)
BYTES_NOW=$(tunnel_downlink || echo "")
MOVED=0
if [ -n "$BYTES_NOW" ]; then
  echo "$BYTES_NOW" > "$STATE/bytes"
  [ "$BYTES_NOW" -gt "$BYTES_PREV" ] && MOVED=$((BYTES_NOW - BYTES_PREV))
fi

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

# One line per probe, kept in tmpfs. Intermittent faults are invisible to any
# live command — by the time anyone looks, the box is healthy again — so the
# only way to explain one is to have been recording while it happened.
# `gw history` reads this back.
CT_CUR=$(cat "${GW_CONNTRACK:-/proc/sys/net/netfilter}/nf_conntrack_count" 2>/dev/null || echo 0)
CT_MAX=$(cat "${GW_CONNTRACK:-/proc/sys/net/netfilter}/nf_conntrack_max" 2>/dev/null || echo 0)
RSS=$(ps -o rss= -C xray 2>/dev/null | awk '{s+=$1} END{printf "%d", s/1024}')
printf '%s %s ct=%s/%s rss=%sM load=%s rx=+%s\n' \
  "$(date -u +%FT%TZ)" "$STATUS" "$CT_CUR" "$CT_MAX" "${RSS:-0}" \
  "$(cut -d' ' -f1 /proc/loadavg)" "$MOVED" >> "$STATE/history"
# Trim to roughly a day of samples, so a long-running box cannot fill tmpfs.
KEEP=$((86400 / ${INTERVAL:-30} + 60))
if [ "$(wc -l < "$STATE/history")" -gt "$((KEEP * 2))" ]; then
  tail -n "$KEEP" "$STATE/history" > "$STATE/history.tmp" \
    && mv "$STATE/history.tmp" "$STATE/history"
fi

# A full conntrack table drops NEW connections while leaving established ones
# alone, which on a client looks like the internet coming and going. Say so
# before it fills, not after.
if [ "$CT_MAX" -gt 0 ] && [ "$((CT_CUR * 100 / CT_MAX))" -ge 80 ]; then
  log warning "conntrack $CT_CUR/$CT_MAX (>=80%) — new connections get dropped once it fills; raise net.netfilter.nf_conntrack_max"
fi

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
  # Restarting is not free: it kills every live connection on every client.
  # If the tunnel received bytes during this very cycle it is carrying
  # traffic, whatever the probe thinks, and restarting would manufacture the
  # outage the probe only suspected.
  if [ "$MOVED" -gt 0 ] && [ "$STATUS" != degraded ]; then
    log warning "probe failed $FAILS times but the tunnel received $MOVED bytes this cycle — NOT restarting xray (that would drop every live connection). Suspect the probe URL, not the tunnel."
  else
    log err "restarting xray after $FAILS failed probes"
    systemctl restart xray
  fi
fi

if [ "$FAILS" -eq "$FALLBACK_AFTER" ]; then
  log err "still down after $FAILS probes — check the server, the XHTTP params, and the clock ($(date -u +%FT%TZ))"
fi

if [ "$LIFELINE_MIN" -gt 0 ]; then
  DOWN_SEC=$((FAILS * INTERVAL))
  [ "$DOWN_SEC" -ge $((LIFELINE_MIN * 60)) ] && lifeline_on
fi
exit 0
