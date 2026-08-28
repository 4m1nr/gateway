#!/usr/bin/env bash
# Offline test suite. Runs anywhere — no gateway, no root, no network.
#
# Every fixture is rendered and the resulting nftables ruleset is fed to a real
# `nft -c`, inside an unprivileged user namespace when not run as root. That
# catches syntax and semantic errors (overlapping intervals, bad matches)
# before they can take the LAN offline.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export PYTHONPATH="$PWD/lib"

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s✓%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s✗%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

OUT=$(mktemp -d); trap 'rm -rf "$OUT"' EXIT

nft_check() {
  # `meta skuid "xray"` is resolved to a numeric uid when nft PARSES the file,
  # so validating the ruleset verbatim only works on a machine where the
  # gateway is already installed. On a CI runner or a contributor's laptop it
  # fails with "User does not exist" — a fact about the environment, not a
  # defect in the ruleset.
  #
  # Substitute a user that exists everywhere for the parse. The real username
  # is still asserted separately by the loop-guard check below, so this cannot
  # hide the rule going missing.
  local src="$1" checked="$1.usercheck"
  sed 's/meta skuid "xray"/meta skuid "root"/' "$src" > "$checked"

  local out
  if [ "$(id -u)" -eq 0 ]; then out=$(nft -c -f "$checked" 2>&1)
  elif unshare -rn true 2>/dev/null; then out=$(unshare -rn nft -c -f "$checked" 2>&1)
  else rm -f "$checked"; echo "SKIP"; return; fi
  rm -f "$checked"
  printf '%s' "$out"
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
  # Job scripts run as root and may carry credentials; the generic
  # gateway/*.sh case glob used to match them too and install them 755.
  if [ -d "$OUT/$name/usr/local/lib/gateway/jobs" ]; then
    badmode=$(find "$OUT/$name/usr/local/lib/gateway/jobs" -name '*.sh' \
              ! -perm 700 -printf '%f ' 2>/dev/null)
    if [ -z "$badmode" ]; then ok "$name: job scripts are 700"
    else bad "$name: job scripts not 700: $badmode"; fi
  fi

  if grep -q 'comment "killswitch"' "$OUT/$name/etc/nftables.d/gateway.nft"; then
    ok "$name: killswitch rule present"
  else bad "$name: KILLSWITCH RULE MISSING"; fi

  # The box's own traffic is marked in output, looped back through lo by policy
  # routing, and can only be intercepted in prerouting. If the loopback
  # shortcut comes first, those packets vanish and the box has no internet
  # while LAN clients work and the SOCKS health probe still says "tunnel up" —
  # which is a genuinely awful thing to debug.
  nftf="$OUT/$name/etc/nftables.d/gateway.nft"
  pre=$(sed -n '/chain prerouting/,/^    }/p' "$nftf")
  lo_tproxy=$(printf '%s' "$pre" | grep -n 'iif lo meta mark' | head -1 | cut -d: -f1)
  lo_return=$(printf '%s' "$pre" | grep -n '^ *iif lo return' | head -1 | cut -d: -f1)
  if [ -n "$lo_tproxy" ] && [ -n "$lo_return" ] && [ "$lo_tproxy" -lt "$lo_return" ]; then
    ok "$name: looped-back local traffic is intercepted before the lo shortcut"
  else
    bad "$name: prerouting returns on lo before intercepting marked local traffic — the box will have no internet"
  fi

  # Performance settings have to reach the generated config, or tuning them
  # looks like it works and changes nothing.
  if python3 -c "
import json,sys;sys.path.insert(0,'lib');import gwconfig
c = gwconfig.load('$f'); d = json.load(open('$OUT/$name/usr/local/etc/xray/config.json'))
lvl = d['policy']['levels']['0']
if c.buffer_size_kb >= 0:
    assert lvl['bufferSize'] == c.buffer_size_kb, 'bufferSize not applied'
else:
    assert 'bufferSize' not in lvl, 'bufferSize set when it should be left alone'
assert lvl['connIdle'] == c.conn_idle, 'connIdle not applied'
if c.tcp_congestion:
    for o in d['outbounds']:
        if o.get('protocol') == 'blackhole':
            continue
        s = o['streamSettings']['sockopt']
        assert s.get('tcpcongestion') == c.tcp_congestion, o['tag']
"; then
    ok "$name: performance settings reach the Xray config"
  else bad "$name: performance settings are not applied"; fi

  # A poisoned-DNS drop that overlapped the LAN would break local traffic; one
  # that missed 10.10.34.34 would not do its job.
  if grep -q 'poisoned-dns' "$nftf"; then
    if python3 -c "
import ipaddress, sys
sys.path.insert(0,'lib'); import gwconfig
c = gwconfig.load('$f')
lan = ipaddress.ip_network(c.lan_cidr)
nets = [ipaddress.ip_network(x) for x in c.poisoned_dst]
assert not any(n.overlaps(lan) for n in nets), 'overlaps the LAN'
assert any(ipaddress.ip_address('10.10.34.34') in n for n in nets), 'misses 10.10.34.34'
"; then
      ok "$name: poisoned-dns set excludes the LAN and catches private answers"
    else bad "$name: poisoned-dns set is wrong (see above)"; fi
  fi

  # dns.intercept only works if port 53 is excluded from tproxy: mangle runs at
  # -150 and nat prerouting at -100, so tproxy would swallow it first and the
  # redirect would sit there doing nothing.
  if grep -q 'chain dnsintercept' "$nftf"; then
    if grep -q 'dport != 53' "$nftf"; then
      ok "$name: DNS interception is reachable (port 53 excluded from tproxy)"
    else bad "$name: dnsintercept chain exists but tproxy still swallows port 53"; fi
  fi

  # Redirecting to a loopback address makes every packet arriving on a real
  # interface a martian, dropped by the kernel during the route lookup —
  # after the rule's counter has already counted it. The box's own traffic
  # still works (it is looped through lo), so this looks like "clients are
  # broken" rather than "the tproxy target is wrong".
  if grep -q 'tproxy ip to 127\.' "$nftf"; then
    bad "$name: tproxy redirects to loopback — LAN clients will be dropped as martians"
  elif grep -q 'tproxy ip to :' "$nftf"; then
    ok "$name: tproxy keeps the original destination address"
  else bad "$name: no tproxy rule found"; fi

  # A TPROXY-delivered packet is addressed to an external IP and delivered
  # locally, which conntrack is inclined to call invalid. Accepting on the mark
  # has to come first, or the client's SYNs die between the tproxy verdict and
  # Xray's socket while the prerouting counters show them intercepted.
  inp=$(sed -n '/chain input {/,/^    }/p' "$nftf")
  mark_at=$(printf '%s' "$inp" | grep -n 'input-intercepted' | head -1 | cut -d: -f1)
  invalid_at=$(printf '%s' "$inp" | grep -n 'input-invalid' | head -1 | cut -d: -f1)
  if [ -n "$mark_at" ] && [ -n "$invalid_at" ] && [ "$mark_at" -lt "$invalid_at" ]; then
    ok "$name: input accepts intercepted packets before the conntrack check"
  else
    bad "$name: input drops ct-invalid before accepting intercepted packets"
  fi

  # Silent drops are how the last three bugs stayed hidden.
  missing_counter=""
  for want in input-intercepted prerouting-unmatched dropped-input; do
    grep -q "$want" "$nftf" || missing_counter="$missing_counter $want"
  done
  # Only when v6 is actually being dropped; ipv6.mode = "pass" has no such rule.
  if grep -q 'nfproto ipv6' "$nftf"; then
    grep -q 'ipv6-dropped' "$nftf" || missing_counter="$missing_counter ipv6-dropped"
  fi
  if [ -z "$missing_counter" ]; then
    ok "$name: every silent-drop path carries a named counter"
  else bad "$name: uncounted drop path(s):$missing_counter"; fi

  # The loop guards are equally load-bearing: without them the box wedges the
  # moment interception is enabled.
  if grep -q 'meta mark \$MARK_XRAY return' "$nftf" && grep -q 'meta skuid "xray" return' "$nftf"; then
    ok "$name: both output-chain loop guards present"
  else bad "$name: loop guard missing from the output chain"; fi

  # Outbounds are pasted verbatim now, so the gateway imposing tag + mark on
  # every one of them is the invariant that keeps the box from deadlocking.
  mark=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(gwconfig.load('$f').outbound_mark)")
  if out=$(python3 tests/check_outbounds.py "$OUT/$name/usr/local/etc/xray/config.json" "$mark" 2>&1); then
    ok "$name: ${out#ok: }"
  else bad "$name: $out"; fi

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
      # Anchored on the rule comment: the rule text carries counters and
      # exclusions that change, the comment names what the rule is for.
      if grep -q 'lan-intercepted' "$nftf" && grep -q 'killswitch-default' "$nftf"; then
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
  if grep -q 'self-or-router' "$nftf"; then
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

  # ---- custom routes ----
  nroutes=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(len(gwconfig.load('$f').routes))")
  if [ "$nroutes" -gt 0 ]; then
    if out=$(python3 tests/check_custom_routes.py "$f" \
             "$OUT/$name/usr/local/etc/xray/config.json" 2>&1); then
      ok "$name: ${out#ok: }"
    else bad "$name: $out"; fi
  fi

  # ---- geodata + bootstrap proxy reach the scripts ----
  envf="$OUT/$name/usr/local/lib/gateway/env"
  geo=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(gwconfig.load('$f').geo_url)")
  prox=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(gwconfig.load('$f').bootstrap_proxy)")
  # Source it, the way the helpers do — that also proves the file is
  # shell-safe, which an unquoted value with a space would not be.
  # shellcheck disable=SC1090  # the path is a per-fixture build directory
  if envout=$( . "$envf" 2>/dev/null && printf '%s|%s|%s' \
                 "$GEO_URL_TEMPLATE" "$BOOTSTRAP_PROXY" "$GEO_FILES" ); then
    if [ "${envout%%|*}" = "$geo" ]; then
      ok "$name: geodata source reaches the update script"
    else bad "$name: GEO_URL_TEMPLATE is '${envout%%|*}', expected '$geo'"; fi
    rest="${envout#*|}"
    if [ "${rest%%|*}" = "$prox" ]; then
      ok "$name: bootstrap proxy setting reaches the scripts"
    else bad "$name: BOOTSTRAP_PROXY is '${rest%%|*}', expected '$prox'"; fi
    want_files=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(' '.join(gwconfig.load('$f').geo_files))")
    if [ "${envout##*|}" = "$want_files" ]; then
      ok "$name: env round-trips through a shell source"
    else bad "$name: GEO_FILES came back as '${envout##*|}', expected '$want_files'"; fi
  else
    bad "$name: the env file could not be sourced — a value is not shell-safe"
  fi

  # ---- scheduled jobs ----
  njobs=$(python3 -c "
import sys;sys.path.insert(0,'lib');import gwconfig
print(len(gwconfig.load('$f').jobs))")
  if [ "$njobs" -gt 0 ]; then
    cron="$OUT/$name/etc/cron.d/gw-jobs"
    # A crontab line containing % is silently truncated by cron at that point,
    # so script bodies must live in their own files. This is the whole reason
    # the crontab only ever names a script.
    if grep -vE '^\s*#' "$cron" | grep -q '%'; then
      bad "$name: a % reached the crontab — cron would truncate that line"
    else ok "$name: no % in the crontab (script bodies are in their own files)"; fi

    if python3 tests/check_jobs.py "$f" "$OUT/$name" >/dev/null 2>&1; then
      ok "$name: every enabled job has a crontab line and a script"
    else
      bad "$name: $(python3 tests/check_jobs.py "$f" "$OUT/$name" 2>&1 | head -1)"
    fi
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
    # Two spellings of the same single command: via systemd-run (which is how
    # the helper gets outside gw-web's sandbox) and bare (the fallback). Both
    # must be written out in full, so the grant stays exact-match.
    bare=$(grep -cE '^gwweb .*NOPASSWD: */usr/local/lib/gateway/web-action\.py *$' "$sudoers")
    viarun=$(grep -cE '^gwweb .*NOPASSWD: */usr/bin/systemd-run --pipe --wait --collect --quiet /usr/local/lib/gateway/web-action\.py *$' "$sudoers")
    if [ "$bare" -eq 1 ] && [ "$viarun" -eq 1 ]; then
      ok "$name: sudoers grants exactly the two fixed helper invocations"
    else bad "$name: sudoers grants are not the expected exact commands (bare=$bare systemd-run=$viarun)"; fi

    # Every grant line must name a full command; a bare interpreter or a
    # directory would be a much broader grant than it looks.
    if grep -E '^gwweb' "$sudoers" | grep -qvE 'NOPASSWD: .*/web-action\.py *$'; then
      bad "$name: a sudoers grant does not end in web-action.py"
    else ok "$name: every sudo grant ends at the helper itself"; fi
    if grep -qE 'NOPASSWD:.*[*]' "$sudoers"; then
      bad "$name: SUDOERS CONTAINS A WILDCARD"
    else ok "$name: no wildcard in the sudo grant"; fi
    if command -v visudo >/dev/null; then
      visudo -cf "$sudoers" >/dev/null 2>&1 \
        && ok "$name: sudoers parses" || bad "$name: sudoers does NOT parse"
    fi

    # The web process must stay sandboxed, and the privileged helper must
    # leave that sandbox — a sudo'd child inherits the service's mount
    # namespace, so without this the helper is root on a read-only filesystem
    # and every dashboard write fails with EROFS.
    if grep -q '^ProtectSystem=strict' "$units/gw-web.service"; then
      ok "$name: gw-web keeps its filesystem sandbox"
    else bad "$name: gw-web no longer sets ProtectSystem=strict"; fi

    # The dashboard must reach the helper through systemd-run, or it inherits
    # this service's read-only mount namespace and its no-namespaces seccomp
    # filter — the two together make every write fail as root.
    if grep -q 'systemd-run' lib/webapp.py; then
      ok "$name: the dashboard invokes the helper outside its own sandbox"
    else bad "$name: webapp.py calls the helper with plain sudo — it will inherit the sandbox"; fi

    helper="$OUT/$name/usr/local/lib/gateway/web-action.py"
    if grep -q 'def escape_service_sandbox' "$helper" \
       && grep -q 'escape_service_sandbox()' "$helper"; then
      ok "$name: the privileged helper escapes the service sandbox"
    else bad "$name: web-action.py does not leave gw-web's mount namespace"; fi

    # sudo needs setuid, so this one hardening knob has to stay off; asserting
    # it stops a future "tighten the unit" change from silently breaking auth.
    if grep -q '^NoNewPrivileges=false' "$units/gw-web.service"; then
      ok "$name: gw-web keeps NoNewPrivileges off (sudo needs it)"
    else bad "$name: gw-web sets NoNewPrivileges=true — sudo will fail"; fi

    # web.json is world-readable, so the real question is whether any actual
    # secret leaked into it. ("key" appears legitimately as a TLS key *path*.)
    uuid=$(python3 tests/secret_of.py "$f")
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
echo "== setup network calls honour the bootstrap proxy =="
# Setup runs before the tunnel carries traffic, so anything fetching from an
# external host must go through gw_curl (which applies bootstrap.socks_proxy)
# and must be bounded. A bare curl here hangs for five minutes and then fails
# on exactly the networks this box exists to work around.
#
# Line continuations are joined first: a curl whose URL sits on the next line
# is the normal way these are written, and a naive per-line check misses it.
offenders=""
missing_timeout=""
for f in scripts/*.sh templates/lib/*.sh; do
  base=$(basename "$f")
  [ "$base" = "net.sh" ] && continue          # this is where gw_curl is defined
  joined=$(sed -e ':a' -e '/\\$/N; s/\\\n//; ta' "$f" | grep -vE '^[[:space:]]*#')

  while IFS= read -r line; do
    case "$line" in *curl*) ;; *) continue ;; esac
    # Deliberate exceptions, each for a reason:
    #   socks5-hostname  a probe through the local Xray, not an external fetch
    #   gw_as_user xray  the leak test, which must bypass the tunnel by design
    #   curl -6          the IPv6 probe, testing whether v6 egress exists at all
    case "$line" in
      *socks5-hostname*|*"gw_as_user xray"*|*"curl -6"*) continue ;;
      # Explicitly marked as needing a direct, unproxied request. Used by the
      # health and verify probes, which exist to test the interception path —
      # routing them through a proxy would bypass what they measure.
      *gw:direct-ok*) continue ;;
    esac
    case "$line" in
      *gw_curl*)
        case "$line" in
          *--max-time*) ;;
          *) missing_timeout="$missing_timeout $base" ;;
        esac ;;
      *curl*http*|*curl*"$"*) offenders="$offenders $base" ;;
    esac
  done <<EOFJOINED
$joined
EOFJOINED
done

# The marker must sit on the curl line itself. On its own comment line it would
# be stripped before the check ever sees it, and would silently exempt nothing
# while looking like it did.
stray_markers=""
for f in scripts/*.sh templates/lib/*.sh; do
  grep -q 'gw:direct-ok' "$f" 2>/dev/null || continue
  if grep 'gw:direct-ok' "$f" | grep -qv 'curl'; then
    stray_markers="$stray_markers $(basename "$f")"
  fi
done
if [ -n "$stray_markers" ]; then
  bad "gw:direct-ok is on a line with no curl in:$stray_markers"
else
  ok "every gw:direct-ok marker sits on the invocation it exempts"
fi

if [ -z "$offenders" ]; then
  ok "no bare curl to an external host in the setup scripts"
else
  bad "bare curl (bypasses the bootstrap proxy) in:$(echo "$offenders" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
fi
if [ -z "$missing_timeout" ]; then
  ok "every gw_curl call sets --max-time"
else
  bad "gw_curl without --max-time in:$(echo "$missing_timeout" | tr ' ' '\n' | sort -u | tr '\n' ' ')"
fi

echo
echo "== rp_filter is disabled on every interface, not just the WAN =="
# The reverse-path check before local delivery runs with mark 0, so it skips
# the fwmark rule and can land in another table (Tailscale installs one that
# matches everything). With rp_filter on, the mismatch is a martian and the
# packet dies between prerouting and input with no counter anywhere.
# The effective value is max(all, <iface>), so setting `all` alone is not enough.
if grep -q 'for f in /proc/sys/net/ipv4/conf/\*/rp_filter' templates/lib/ip-rules.sh; then
  ok "ip-rules.sh clears rp_filter on every interface"
else
  bad "ip-rules.sh only sets rp_filter for some interfaces — later ones (tailscale0) will keep the default"
fi
if grep -q 'reverse (validation, mark 0)' bin/gw; then
  ok "gw diag shows the reverse-path lookup"
else bad "gw diag does not show the reverse-path lookup"; fi

# The reverse lookup must resolve in main, ahead of Tailscale's catch-all rule
# at priority 5270, or validation can reject LAN clients as martians.
if grep -q 'ip rule add to "$LAN_CIDR" lookup main pref 90' templates/lib/ip-rules.sh; then
  ok "reverse-path lookups for the LAN are pinned to the main table"
else
  bad "no rule pinning LAN reverse-path lookups to main — another table can claim them"
fi

# A failing probe inside gw diag is a result, not an error; under set -e an
# unguarded failure aborted the rest of the report, hiding the data.
if grep -q 'ip route get "$probe_dst" from "$client" iif "$wan" mark 1 2>&1 || true' bin/gw; then
  ok "gw diag survives a failing route probe"
else bad "gw diag aborts when a route probe fails"; fi

echo
echo "== sbin tools are reachable regardless of the caller's PATH =="
# nft, sysctl and ip live in /usr/sbin, which is absent from some root PATHs.
# Calling them by bare name made `gw status` report "firewall not loaded"
# purely because it could not find nft, while `sudo gw apply` worked (sudo's
# secure_path includes /usr/sbin). The disagreement looked like the firewall
# was vanishing.
for f in bin/gw lib/common.sh templates/lib/net.sh; do
  if grep -q 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' "$f"; then
    ok "$(basename "$f") sets an explicit PATH"
  else
    bad "$(basename "$f") does not set PATH — sbin tools may be unreachable"
  fi
done

# The assignment has to come before anything uses those tools.
first_path=$(grep -n '^PATH=' bin/gw | head -1 | cut -d: -f1)
first_use=$(grep -nE '^[^#]*\b(nft|sysctl|ip) ' bin/gw | head -1 | cut -d: -f1)
if [ -n "$first_path" ] && [ -n "$first_use" ] && [ "$first_path" -lt "$first_use" ]; then
  ok "gw sets PATH before its first sbin tool call"
else
  bad "gw uses an sbin tool at line ${first_use:-?} before setting PATH at line ${first_path:-none}"
fi

# And a missing tool must say so rather than being read as "no firewall".
if grep -q 'required command %s not found on PATH' bin/gw; then
  ok "gw fails loudly when a required tool is missing"
else
  bad "gw does not check that nft/ip are present"
fi

if env -i PATH=/usr/bin:/bin HOME=/tmp bash bin/gw help >/dev/null 2>&1; then
  ok "gw runs with a stripped environment"
else
  bad "gw fails with a minimal PATH"
fi

echo
echo "== awk programs actually parse =="
# `printf "%.1f", x>0 ? a : b` is a SYNTAX ERROR in awk: the > is parsed as
# output redirection. It fails silently inside a shell pipeline and produces
# empty output, which is exactly how gw bench reported two blank measurements.
awk_bad=0
while IFS= read -r prog; do
  printf '%s' "$prog" | awk -f /dev/stdin </dev/null >/dev/null 2>&1 || awk_bad=$((awk_bad + 1))
done <<'PROGS'
BEGIN { d = 1; printf "%.1f
", (d > 0 ? 400 / d : 0) }
PROGS
if [ "$awk_bad" -eq 0 ]; then
  ok "sample awk program parses"
else bad "an awk program failed to parse"; fi

# The real guard: no unparenthesised comparison in a print/printf argument.
if grep -nE '(printf|print)[^;]*,[^;]*[a-z0-9_]+ *> *[0-9]' bin/gw | grep -v '(' >/dev/null 2>&1; then
  bad "bin/gw has a print/printf with an unparenthesised > (awk parses it as redirection)"
else
  ok "no unparenthesised > inside a print argument"
fi

# curl writes its -w output even on failure, so an `|| echo` fallback appends
# a second value and corrupts the parse.
if grep -q "size_download}' \"\$url\" 2>/dev/null || echo" bin/gw; then
  bad "gw bench appends a fallback to curl -w output, which corrupts the parse"
else
  ok "gw bench parses curl -w output without a corrupting fallback"
fi

echo
echo "== intermittent-fault evidence =="
# A fault that comes and go defeats every live command: by the time anyone runs
# `gw diag` the box is healthy again, and healthy is exactly what it reports.
# So the box has to record while it happens, and gw history has to read it back.
if grep -q 'history) shift; cmd_history' bin/gw && grep -q '^#   gw history' bin/gw; then
  ok "gw history is dispatched and documented"
else
  bad "gw history is missing from the dispatcher or the usage block"
fi

if bash bin/gw help 2>/dev/null | grep -q 'gw history'; then
  ok "gw help lists history"
else
  bad "gw help does not list history"
fi

if grep -q 'STATE/history' templates/lib/health.sh; then
  ok "the health probe records one sample per run"
else
  bad "the health probe records nothing, so an intermittent fault leaves no trace"
fi

# The ring buffer lives in tmpfs and must be bounded, or a box up for months
# fills /run.
if grep -q 'tail -n "\$KEEP" "\$STATE/history"' templates/lib/health.sh; then
  ok "the sample ring buffer is trimmed"
else
  bad "the sample ring buffer grows without bound in tmpfs"
fi

# Restarting Xray drops every live connection on every client. A watchdog that
# does that on one timed-out probe manufactures the outage it exists to catch.
probe_curls=$(sed -n '/^probe_intercepted()/,/^}/p' templates/lib/health.sh | grep -c 'curl ')
if [ "$probe_curls" -ge 2 ]; then
  ok "the health probe retries before declaring a failure ($probe_curls attempts)"
else
  bad "the health probe declares failure on a single timeout, and the failure path restarts Xray"
fi

if grep -q 'NOT restarting xray' templates/lib/health.sh; then
  ok "a tunnel that is moving bytes is not restarted out from under its clients"
else
  bad "the health probe restarts Xray even when the tunnel is demonstrably passing traffic"
fi

# The evidence that guard depends on: sum the downlink of real outbounds only.
# Direct and block prove nothing about the tunnel, and uplink only proves
# something wrote into a socket that may already be dead.
python3 - <<'PYEXTRACT' > "$OUT/downlink.awk"
import re, pathlib
src = pathlib.Path("templates/lib/health.sh").read_text()
m = re.search(r"awk -F'\"' '(.*?)'\n", src, re.S)
if not m:
    raise SystemExit("could not find the stats awk program in health.sh")
print(m.group(1))
PYEXTRACT
cat > "$OUT/stats.json" <<'PYSTATS'
{
 "stat": [
  {
   "name": "outbound>>>proxy>>>traffic>>>downlink",
   "value": "1000"
  },
  {
   "name": "outbound>>>proxy>>>traffic>>>uplink",
   "value": "500"
  },
  {
   "name": "outbound>>>direct>>>traffic>>>downlink",
   "value": "9999"
  },
  {
   "name": "outbound>>>block>>>traffic>>>downlink",
   "value": "4"
  },
  {
   "name": "inbound>>>tproxy>>>traffic>>>downlink",
   "value": "7777"
  },
  {
   "name": "outbound>>>work>>>traffic>>>downlink",
   "value": "23"
  }
 ]
}
PYSTATS
got=$(awk -F'"' -f "$OUT/downlink.awk" "$OUT/stats.json" 2>&1)
if [ "$got" = "1023" ]; then
  ok "tunnel downlink counts proxied outbounds only (1000+23)"
else
  bad "tunnel downlink parse returned '$got', expected 1023 (direct/block/uplink/inbound must not count)"
fi

# A restart is itself an outage — it drops every live connection on every
# client — and it leaves no trace once it is over, so gw status has to show how
# long Xray has been up. But ActiveEnterTimestamp outlives the stop, and GNU
# date reads an empty -d argument as midnight today instead of failing, so an
# unguarded version reports a confident uptime for a service that is not
# running at all.
if [ "$(date -d "" +%s 2>/dev/null || echo 0)" != "0" ]; then
  ok "date -d \"\" really does return a time rather than failing (the trap is real)"
else
  ok "date -d \"\" fails on this system"
fi
if grep -q '\[ -n "\$started" \] && epoch=' bin/gw; then
  ok "gw status guards the empty start timestamp before handing it to date"
else
  bad "gw status passes a possibly-empty timestamp to date, which yields midnight today"
fi
if systemctl is-active --quiet xray 2>/dev/null; then
  ok "xray is running here; skipping the inactive-uptime check"
elif GW_REPO="$PWD" bash bin/gw status 2>/dev/null | grep -q 'xray up'; then
  bad "gw status reports an uptime for an xray that is not running"
else
  ok "gw status reports xray uptime only while it is running"
fi

# The other half of the split: AdGuard already records, per client, whether the
# client was still asking this box anything. A gap there is the client leaving,
# not the gateway failing — and the histogram has to show the gap, not skip it.
AGHDIR="$OUT/agh"; mkdir -p "$AGHDIR"
python3 - "$AGHDIR/querylog.json" <<'PYAGH'
import json, pathlib, sys, time
now = time.time()
lines = []
for hour in (5, 4, 2, 1, 0):          # hour 3 is deliberately missing
    for i in range(10):
        stamp = time.localtime(now - hour * 3600 - i * 10)
        lines.append(json.dumps({"T": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", stamp),
                                 "IP": "192.168.1.87"}))
lines.append(json.dumps({"T": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.localtime(now)),
                         "IP": "192.168.1.99"}))
pathlib.Path(sys.argv[1]).write_text("\n".join(lines) + "\n")
PYAGH
hist=$(GW_AGH_LOG="$AGHDIR/querylog.json" GW_REPO="$PWD" bash bin/gw history 6 192.168.1.87 2>&1 \
       | sed -n '/DNS queries/,/^$/p')
if printf '%s' "$hist" | grep -q 'silence'; then
  ok "the DNS histogram flags the hour the client went quiet"
else
  bad "the DNS histogram does not show a gap in client queries"
fi
if [ "$(printf '%s' "$hist" | grep -c '^  20')" -eq 6 ]; then
  ok "the DNS histogram prints every hour in the window, gaps included"
else
  bad "the DNS histogram skipped hours: $(printf '%s' "$hist" | grep -c '^  20') rows, expected 6"
fi
# Another client's queries must not fill in this client's silence.
if printf '%s' "$hist" | grep -q '192.168.1.99'; then
  bad "the DNS histogram is not filtered by client"
else
  ok "the DNS histogram counts only the client asked about"
fi

# A stat whose value Xray omits (it omits zeroes) must not hand its name to the
# next stat's value.
cat > "$OUT/stats-sparse.json" <<'PYSPARSE'
{
 "stat": [
  {
   "name": "outbound>>>proxy>>>traffic>>>downlink"
  },
  {
   "name": "outbound>>>direct>>>traffic>>>downlink",
   "value": "9999"
  }
 ]
}
PYSPARSE
got=$(awk -F'"' -f "$OUT/downlink.awk" "$OUT/stats-sparse.json" 2>&1)
if [ "$got" = "0" ]; then
  ok "an omitted stat value is not misattributed to the next stat"
else
  bad "omitted stat value misparsed: got '$got', expected 0"
fi

echo
echo "== gw diff reflects the config you just edited =="
# It used to render only when build/ was missing. After the first apply that
# meant comparing last time's build tree against the files installed from it —
# identical by construction — so `gw diff` answered "no changes" whatever you
# had edited. Silent and confident, which is the worst combination.
if sed -n '/^cmd_diff()/,/^}/p' bin/gw | grep -q '\[ -d "\$BUILD" \]'; then
  bad "gw diff renders only when build/ is missing, so it compares a stale tree"
else
  ok "gw diff has no stale-build shortcut"
fi

# The fixture's outbound is a relative path, resolved against the config's own
# directory, so a copy needs the outbounds tree beside it.
cp -r tests/fixtures/outbounds "$OUT/outbounds"
DIFFCFG="$OUT/diff-edit.toml"
cp tests/fixtures/default.toml "$DIFFCFG"
GW_REPO="$PWD" GW_CONFIG="$DIFFCFG" bash bin/gw diff >/dev/null 2>&1 || true
before=$(cat build/usr/local/lib/gateway/env 2>/dev/null || echo missing)
sed -i 's/^tproxy_port.*/tproxy_port = 12346/' "$DIFFCFG"
GW_REPO="$PWD" GW_CONFIG="$DIFFCFG" bash bin/gw diff >/dev/null 2>&1 || true
after=$(cat build/usr/local/lib/gateway/env 2>/dev/null || echo missing)
if [ "$before" != "$after" ] && printf '%s' "$after" | grep -q 'TPROXY_PORT="12346"'; then
  ok "editing gateway.toml changes what gw diff compares"
else
  bad "gw diff did not re-render after the config changed"
fi

echo
echo "== status reads back cleanly =="
# nft wraps a long element list and indents the continuation with TABS, so
# squeezing spaces alone leaves a ragged gap in the middle of the list.
setout=$(
  eval "$(sed -n '/^gw_set_elements()/,/^}/p' bin/gw)"
  nft() { printf 'table inet gateway {\n\tset proxy_clients {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = { 100.64.0.0/10, 192.168.1.20,\n\t\t\t     192.168.1.87 }\n\t}\n}\n'; }
  gw_set_elements proxy_clients
)
if [ "$setout" = "100.64.0.0/10, 192.168.1.20, 192.168.1.87" ]; then
  ok "wrapped nft set elements read back on one clean line"
else
  bad "set elements came back as '$setout'"
fi

# `tailscale status | head -3` cut off one line into the "# Health check:"
# header: it printed the heading and hid every warning under it, which is the
# only part that says what is wrong.
TSBIN="$OUT/tsbin"; mkdir -p "$TSBIN"
cat > "$TSBIN/tailscale" <<'TSEOF'
#!/bin/sh
printf '100.86.70.57  gateway  someone@  linux  idle; offers exit node\n\n'
printf '# Health check:\n#     - not connected to home DERP region 1\n'
printf '#     - Tailscale can not reach the configured DNS servers\n'
TSEOF
chmod +x "$TSBIN/tailscale"
tsout=$(PATH="$TSBIN:$PATH" GW_REPO="$PWD" bash bin/gw status 2>&1 || true)
if printf '%s' "$tsout" | grep -q 'not connected to home DERP' \
   && printf '%s' "$tsout" | grep -q 'reach the configured DNS'; then
  ok "gw status shows every Tailscale health warning, not just the heading"
else
  bad "gw status truncates Tailscale's health check"
fi
if printf '%s' "$tsout" | grep -q '100.86.70.57'; then
  ok "gw status still shows the Tailscale address line"
else
  bad "gw status dropped the Tailscale status line"
fi

echo
echo "== scheduled updates =="
# Geodata had a daily timer; Xray and AdGuard had nothing at all. They updated
# only when somebody remembered to run `gw update` by hand, which is not what
# "auto updates" means to anyone.
if grep -q '^    services)' bin/gw; then
  ok "gw update services exists (what the timer runs)"
else
  bad "gw update has no 'services' target for the scheduled updater"
fi

# The setting has to exist in the example, or every mode below silently tests
# the same default.
if grep -q '^auto_update ' tests/fixtures/default.toml; then
  ok "auto_update is a documented setting, not an undocumented flag"
else
  bad "auto_update is missing from gateway.example.toml"
fi

for mode in check services all; do
  cfg="$OUT/au-$mode.toml"
  sed "s/^auto_update  *=.*/auto_update = \"$mode\"/" tests/fixtures/default.toml > "$cfg"
  if python3 lib/render.py "$cfg" "$OUT/au-$mode" >/dev/null 2>&1 \
     && grep -q "gw update $mode\$" "$OUT/au-$mode/etc/systemd/system/gw-update.service"; then
    ok "auto_update=$mode renders a timer that runs exactly that"
  else
    bad "auto_update=$mode did not render a matching gw-update.service"
  fi
done

cfg="$OUT/au-off.toml"
sed 's/^auto_update  *=.*/auto_update = "off"/' tests/fixtures/default.toml > "$cfg"
if python3 lib/render.py "$cfg" "$OUT/au-off" >/dev/null 2>&1; then
  if [ -f "$OUT/au-off/etc/systemd/system/gw-update.timer" ]; then
    bad "auto_update=off still renders the update timer"
  else
    ok "auto_update=off renders no update timer"
  fi
else
  bad "auto_update=off was rejected by the renderer"
fi

# Turning it off has to remove the installed unit too, or the old schedule
# keeps firing and the setting reads as if it worked.
if grep -q 'removing \$stale (no longer in the config)' bin/gw; then
  ok "gw apply removes an update unit that is no longer rendered"
else
  bad "gw apply leaves a de-configured gw-update unit installed and enabled"
fi

cfg="$OUT/au-bad.toml"
sed 's/^auto_update  *=.*/auto_update = "sometimes"/' tests/fixtures/default.toml > "$cfg"
if python3 lib/render.py "$cfg" "$OUT/au-bad" >/dev/null 2>&1; then
  bad "an unknown auto_update mode was accepted"
else
  ok "an unknown auto_update mode is rejected"
fi

# An OnCalendar systemd cannot parse loads fine and then never fires.
if grep -q 'systemd-analyze calendar' bin/gw; then
  ok "gw apply validates the update schedule before installing it"
else
  bad "gw apply installs the update timer without checking its OnCalendar"
fi
cal=$(sed -n 's/^OnCalendar=//p' "$OUT/au-services/etc/systemd/system/gw-update.timer")
if command -v systemd-analyze >/dev/null 2>&1; then
  if systemd-analyze calendar "$cal" >/dev/null 2>&1; then
    ok "the default update schedule ('$cal') is a valid OnCalendar"
  else
    bad "the default update schedule ('$cal') is not a valid OnCalendar"
  fi
else
  ok "systemd-analyze unavailable; skipping the OnCalendar check"
fi

if grep -q 'gw-update.timer' bin/gw; then
  ok "gw-update.timer is part of the managed stack"
else
  bad "gw-update.timer is not in STACK, so enable/disable ignore it"
fi

echo
echo "== entry points resolve through symlinks =="
# The documented install symlinks /usr/local/bin/gw -> /opt/gateway/bin/gw.
# $BASH_SOURCE and $0 report the symlink, not its target, so an unresolved
# dirname computes /usr/local as the repo root and every lookup lands in the
# wrong tree. This is exactly how it broke in the field.
LINKDIR=$(mktemp -d)
ln -sf "$PWD/bin/gw" "$LINKDIR/gw"
if out=$("$LINKDIR/gw" help 2>&1) && printf '%s' "$out" | grep -q "gw init"; then
  ok "bin/gw works through an absolute symlink"
else
  bad "bin/gw through a symlink: ${out%%$'\n'*}"
fi

ln -sf gw "$LINKDIR/gw-chained"
if "$LINKDIR/gw-chained" help >/dev/null 2>&1; then
  ok "bin/gw follows a relative symlink chain"
else bad "bin/gw does not follow a relative symlink chain"; fi

# The scripts source lib/common.sh relative to themselves, which fails before
# common.sh can fix anything — so it has to be resolved by the caller.
ln -sf "$PWD/scripts/90-verify.sh" "$LINKDIR/verify"
out=$("$LINKDIR/verify" 2>&1 || true)
if printf '%s' "$out" | grep -q "common.sh: No such file"; then
  bad "a symlinked script cannot find lib/common.sh"
else ok "install scripts find lib/common.sh through a symlink"; fi

if out=$(GW_REPO="$PWD" "$LINKDIR/gw" help 2>&1) && printf '%s' "$out" | grep -q "gw init"; then
  ok "GW_REPO overrides repo detection"
else bad "GW_REPO override does not work"; fi
rm -rf "$LINKDIR"

echo
echo "== fixtures are generated, not hand-maintained =="
# A fixture that no longer matches the example silently stops exercising what
# it was written for: a .replace() that misses leaves the default in place and
# the test still passes.
if command -v git >/dev/null && git rev-parse --git-dir >/dev/null 2>&1; then
  before=$(git status --porcelain -- tests/fixtures | wc -l)
  python3 tests/make_fixtures.py >/dev/null 2>&1 || bad "make_fixtures.py failed"
  after=$(git status --porcelain -- tests/fixtures | wc -l)
  if [ "$before" -eq "$after" ]; then
    ok "regenerating fixtures is a no-op"
  else
    bad "tests/fixtures is stale — run 'python3 tests/make_fixtures.py' and commit"
  fi
else
  printf '  – not a git checkout, skipping the fixture freshness check\n'
fi

echo
echo "== committed templates =="
# The README and .gitignore both point at these; losing them breaks a new
# install's starting point, and gitignore means git will not warn you.
for tpl in outbounds/main.example.json outbounds/work.example.json; do
  if [ ! -f "$tpl" ]; then bad "$tpl is missing"
  elif ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$tpl" 2>/dev/null; then
    bad "$tpl is not valid JSON"
  elif ! git ls-files --error-unmatch "$tpl" >/dev/null 2>&1; then
    bad "$tpl exists but is not tracked by git (check .gitignore negation)"
  else ok "$(basename "$tpl") present, valid and tracked"; fi
done
stray=0
for f in outbounds/*.json; do
  [ -e "$f" ] || continue
  case "$f" in *.example.json) ;; *) stray=1 ;; esac
done
if [ "$stray" -eq 1 ]; then
  bad "outbounds/ contains non-example .json files — real credentials do not belong in the repo working tree of a test run"
else ok "no stray credential files in outbounds/"; fi

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
