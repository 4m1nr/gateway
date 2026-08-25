#!/usr/bin/env bash
# Offline test suite. Runs anywhere — no gateway, no root, no network.
#
# Every fixture is rendered and the resulting nftables ruleset is fed to a real
# `nft -c`, inside an unprivileged user namespace when not run as root. That
# catches syntax and semantic errors (overlapping intervals, bad matches)
# before they can take the LAN offline.
set -uo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD/lib"

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s✓%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s✗%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT

nft_check() {
  if [ "$(id -u)" -eq 0 ]; then nft -c -f "$1" 2>&1
  elif unshare -rn true 2>/dev/null; then unshare -rn nft -c -f "$1" 2>&1
  else echo "SKIP"; fi
}

echo "== valid fixtures =="
for f in tests/fixtures/*.toml; do
  name=$(basename "$f" .toml)
  if ! err=$(python3 lib/render.py "$f" "$OUT/$name" 2>&1 >/dev/null); then
    bad "$name: render failed: $err"; continue
  fi
  ok "$name: renders"

  if python3 -c "import json,sys;json.load(open(sys.argv[1]))" \
       "$OUT/$name/usr/local/etc/xray/config.json" 2>/dev/null; then
    ok "$name: xray config is valid JSON"
  else bad "$name: xray config is not valid JSON"; fi

  res=$(nft_check "$OUT/$name/etc/nftables.d/gateway.nft")
  if [ "$res" = "SKIP" ]; then
    printf '  – %s: nft check skipped (no userns and not root)\n' "$name"
  elif [ -z "$res" ]; then ok "$name: nftables ruleset accepted by nft -c"
  else bad "$name: nft rejected the ruleset: $res"; fi

  # Shipping a ruleset without the kill switch would silently turn fail-closed
  # into fail-open, which is the one failure mode that must never regress.
  if grep -q 'comment "killswitch"' "$OUT/$name/etc/nftables.d/gateway.nft"; then
    ok "$name: killswitch rule present"
  else bad "$name: KILLSWITCH RULE MISSING"; fi

  # The loop guards are equally load-bearing: without them the box wedges the
  # moment interception is enabled.
  nftf="$OUT/$name/etc/nftables.d/gateway.nft"
  if grep -q 'meta mark \$MARK_XRAY return' "$nftf" && grep -q 'meta skuid "xray" return' "$nftf"; then
    ok "$name: both output-chain loop guards present"
  else bad "$name: loop guard missing from the output chain"; fi

  if grep -q '"mark":' "$OUT/$name/usr/local/etc/xray/config.json"; then
    ok "$name: xray outbounds carry SO_MARK"
  else bad "$name: xray outbounds are missing SO_MARK"; fi

  # Boot behaviour: the target must exist, and every member must declare an
  # [Install] section, or the stack silently fails to come back after a reboot.
  units="$OUT/$name/etc/systemd/system"
  if [ -f "$units/gateway.target" ]; then ok "$name: gateway.target rendered"
  else bad "$name: gateway.target MISSING — nothing ties the stack together"; fi

  missing=""
  for u in gw-network.service xray.service gw-health.timer gw-geoupdate.timer; do
    grep -q '^\[Install\]' "$units/$u" || missing="$missing $u"
  done
  if [ -z "$missing" ]; then ok "$name: every stack unit is installable"
  else bad "$name: no [Install] section in:$missing"; fi

  # PartOf is what makes `systemctl restart gateway.target` propagate.
  missing=""
  for u in gw-network.service xray.service gw-health.timer gw-geoupdate.timer; do
    grep -q '^PartOf=gateway.target' "$units/$u" || missing="$missing $u"
  done
  if [ -z "$missing" ]; then ok "$name: stack units are PartOf gateway.target"
  else bad "$name: PartOf=gateway.target missing from:$missing"; fi

  # The catch-all is what makes "set your gateway to the box and you are
  # proxied" true, so it has to match the configured default exactly.
  nftf="$OUT/$name/etc/nftables.d/gateway.nft"
  pol=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(gwconfig.load('$f').default_policy)")
  case "$pol" in
    proxy)
      if grep -q 'ip saddr \$LAN \\' "$nftf" && grep -q 'killswitch-default' "$nftf"; then
        ok "$name: LAN catch-all intercepts, with a kill switch"
      else bad "$name: default is proxy but the LAN catch-all does not intercept"; fi
      grep -q 'ip saddr \$LAN masquerade' "$nftf" \
        && bad "$name: proxied default must never masquerade the LAN (that is a leak path)" \
        || ok "$name: no LAN masquerade under a proxied default" ;;
    direct)
      if grep -q 'ip saddr \$LAN return' "$nftf" && grep -q 'ip saddr \$LAN masquerade' "$nftf"; then
        ok "$name: LAN catch-all forwards direct, with NAT"
      else bad "$name: default is direct but the catch-all does not forward+NAT"; fi ;;
    block)
      grep -q 'ip saddr \$LAN drop' "$nftf" \
        && ok "$name: LAN catch-all drops" \
        || bad "$name: default is block but the catch-all does not drop" ;;
  esac

  # The box and the router live inside $LAN and must never be swept up by it.
  if grep -q 'ip saddr { \$BOX, \$ROUTER } return' "$nftf"; then
    ok "$name: box and router excluded from the catch-all"
  else bad "$name: box/router not excluded — the catch-all can capture them"; fi

  # ---- profiles ----
  # Rule ORDER is the whole semantic: Xray takes the first match, so an
  # exception below the geo split silently stops working.
  if out=$(python3 tests/check_routing.py "$OUT/$name/usr/local/etc/xray/config.json" 2>&1); then
    ok "$name: routing order — ${out#ok: }"
  else bad "$name: $out"; fi

  profiles=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
c=gwconfig.load('$f');print(','.join(c.profiles))")
  if [ -n "$profiles" ]; then
    xj="$OUT/$name/usr/local/etc/xray/config.json"
    ups=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(','.join(gwconfig.load('$f').upstreams))")
    missing=""
    for u in ${ups//,/ }; do
      grep -q "\"up-$u\"" "$xj" || missing="$missing $u"
    done
    if [ -z "$missing" ]; then ok "$name: every upstream has an outbound"
    else bad "$name: no outbound generated for upstream:$missing"; fi

    # A profile client must be intercepted, or there is nothing to split.
    unintercepted=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
c=gwconfig.load('$f')
srcs=set(c.proxy_sources)
print(','.join(x['ip'] for x in c.clients if x['policy'] in c.profiles and x['ip'] not in srcs))")
    if [ -z "$unintercepted" ]; then ok "$name: all profile clients are intercepted"
    else bad "$name: profile clients not intercepted: $unintercepted"; fi

    # Every route target must resolve to a real outbound tag.
    if python3 -c "
import json,sys;sys.path.insert(0,'lib');import gwconfig
c=gwconfig.load('$f'); d=json.load(open('$xj'))
tags={o['tag'] for o in d['outbounds']} | {'api'}
bad=[r['tag'] for p in c.profiles.values() for r in p['routes'] if r['tag'] not in tags]
sys.exit(1 if bad else 0)"; then
      ok "$name: every profile route points at a real outbound"
    else bad "$name: a profile route names an outbound that does not exist"; fi
  fi

  # ---- web dashboard ----
  web=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print('yes' if gwconfig.load('$f').web_enabled else 'no')")
  sudoers="$OUT/$name/etc/sudoers.d/gw-web"
  if [ "$web" = yes ]; then
    if [ -f "$sudoers" ] && [ -f "$units/gw-web.service" ] \
       && [ -f "$OUT/$name/usr/local/share/gateway/web/app.js" ]; then
      ok "$name: dashboard rendered"
    else bad "$name: web is enabled but the dashboard was not fully rendered"; fi

    # The sudo grant is the dashboard's whole privilege surface. A wildcard
    # here would let a compromised web process run arbitrary gw subcommands.
    if grep -qE '^gwweb .*NOPASSWD: */usr/local/lib/gateway/web-action\.py *$' "$sudoers"; then
      ok "$name: sudoers grants exactly one command, no arguments"
    else bad "$name: sudoers grant is not the single web-action.py entry"; fi
    if grep -qE 'NOPASSWD:.*[*]' "$sudoers"; then
      bad "$name: SUDOERS CONTAINS A WILDCARD"
    else ok "$name: no wildcard in the sudo grant"; fi
    if command -v visudo >/dev/null; then
      visudo -cf "$sudoers" >/dev/null 2>&1 \
        && ok "$name: sudoers parses" || bad "$name: sudoers does NOT parse"
    fi

    # sudo needs setuid, so this one hardening knob has to stay off; asserting
    # it stops a future "tighten the unit" change from silently breaking auth.
    if grep -q '^NoNewPrivileges=false' "$units/gw-web.service"; then
      ok "$name: gw-web keeps NoNewPrivileges off (sudo needs it)"
    else bad "$name: gw-web sets NoNewPrivileges=true — sudo will fail"; fi

    # web.json is world-readable, so the real question is whether any actual
    # secret leaked into it. ("key" appears legitimately as a TLS key *path*.)
    uuid=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(gwconfig.load('$f').server['uuid'])")
    if grep -qF "$uuid" "$OUT/$name/etc/gateway/web.json"; then
      bad "$name: the Xray UUID leaked into world-readable web.json"
    elif grep -qiE '"(password|hash|salt|uuid|secret)" *:' "$OUT/$name/etc/gateway/web.json"; then
      bad "$name: web.json contains a secret-looking field"
    else ok "$name: no credentials in world-readable web.json"; fi

    # Same question for the assets the browser downloads.
    if grep -rqF "$uuid" "$OUT/$name/usr/local/share/gateway/web/"; then
      bad "$name: the Xray UUID leaked into a served web asset"
    else ok "$name: no credentials in the served assets"; fi

    port=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(gwconfig.load('$f').web_port)")
    if grep -q "tcp dport $port accept" "$nftf"; then
      ok "$name: dashboard port firewalled to allow_cidrs"
    else bad "$name: no nftables rule for the dashboard port"; fi
  else
    if [ -f "$sudoers" ] || [ -f "$units/gw-web.service" ]; then
      bad "$name: web is disabled but dashboard files were still rendered"
    else ok "$name: web disabled — no dashboard, no sudoers grant"; fi
  fi

  # tailscaled must NOT be PartOf: restarting the stack would drop the session
  # you are almost certainly using to manage the box.
  if grep -q '^PartOf=gateway.target' "$units/AdGuardHome.service.d/gw.conf" 2>/dev/null \
     && ! grep -rq 'PartOf=gateway.target' "$units/tailscaled.service.d" 2>/dev/null; then
    ok "$name: AdGuard is PartOf the stack, tailscaled is not"
  else bad "$name: tailscaled must not be PartOf gateway.target"; fi
done

echo
echo "== invalid configs must be rejected =="
for f in tests/invalid/*.toml; do
  name=$(basename "$f" .toml)
  if python3 lib/render.py "$f" "$OUT/bad-$name" >/dev/null 2>&1; then
    bad "$name: was ACCEPTED but should have been rejected"
  else
    ok "$name: rejected ($(python3 lib/render.py "$f" "$OUT/bad-$name" 2>&1 | head -1 | cut -c1-70))"
  fi
done

echo
echo "== shell syntax =="
for f in bin/gw scripts/*.sh templates/lib/*.sh lib/common.sh; do
  if bash -n "$f" 2>/dev/null || sh -n "$f" 2>/dev/null; then ok "$(basename "$f")"
  else bad "$(basename "$f") has a syntax error"; fi
done

echo
echo "== python =="
for f in lib/*.py; do
  if python3 -m py_compile "$f" 2>/dev/null; then ok "$(basename "$f")"
  else bad "$(basename "$f") does not compile"; fi
done

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
