#!/usr/bin/env bash
# The three runtime agents: the watchdog, policy routing, and the Tailscale
# bypass.
#
# These run unattended as root and every one of them can take the LAN off the
# internet. The watchdog restarts Xray, which drops every live connection on
# every client, so when it decides to do that matters as much as that it can.
# ip-rules.sh sets the two sysctls without which intercepted packets are
# dropped as martians between prerouting and input, with no counter anywhere.
# ts-bypass.sh punches the only hole in a fail-closed firewall, and the
# guarantee is that the hole fits tailscaled and nothing else.
#
# The scripts are run for real against a scratch tree. Everything that reaches
# outside it — ip, nft, systemctl, curl, xray, logger — is a double that
# records what it was asked to do.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

ROOT=$(mktemp -d); trap 'rm -rf "$ROOT"' EXIT

# ------------------------------------------------------------------ world --

# A scratch box: the paths the scripts write to, and doubles for everything
# they shell out to. Each double appends to $W/calls, which is what most of
# these tests assert against — the question is almost always "did it do this,
# and did it do it before that".
setup() {
  W="$ROOT/$1"; rm -rf "$W"
  mkdir -p "$W"/{bin,lib/gateway,state,conf/eth0,conf/tailscale0,conf/all,conf/lo,netfilter}
  : > "$W/calls"
  : > "$W/log"
  : > "$W/iprules"
  : > "$W/nft"

  cat > "$W/lib/gateway/env" <<'ENV'
LAN_CIDR="192.168.1.0/24"
WAN_IF="eth0"
MARK_TPROXY="1"
RT_TABLE="100"
SOCKS_PORT="10808"
API_PORT="10085"
PROBE_URL="https://example.com/generate_204"
PROBE_TIMEOUT="5"
INTERVAL="30"
RESTART_AFTER="3"
FALLBACK_AFTER="6"
LIFELINE_MIN="5"
ENV

  # rp_filter starts at 1 and accept_local at 0 — the kernel defaults, and the
  # state in which TPROXY delivery silently fails.
  for i in all lo eth0 tailscale0; do
    echo 1 > "$W/conf/$i/rp_filter"
    echo 0 > "$W/conf/$i/accept_local"
  done
  echo 1000 > "$W/netfilter/nf_conntrack_count"
  echo 262144 > "$W/netfilter/nf_conntrack_max"

  # ip: keeps a rule list so idempotence is observable, the way it is on a real
  # box — the script greps its own output before adding.
  cat > "$W/bin/ip" <<IP
#!/usr/bin/env bash
echo "ip \$*" >> "$W/calls"
case "\$1 \$2" in
  "rule add")
    shift 2; pref=""; rest=""
    while [ \$# -gt 0 ]; do
      case "\$1" in
        pref)   pref="\$2"; shift 2 ;;
        # The kernel stores the mark and prints it in hex, so a rule listing
        # never echoes back the decimal it was given. The script greps for the
        # hex form; a fake that skipped this would fake the bug away.
        # (No backticks in here: the heredoc is unquoted and would run them.)
        fwmark) rest="\$rest fwmark \$(printf '0x%x' "\$2")"; shift 2 ;;
        *)      rest="\$rest \$1"; shift ;;
      esac
    done
    printf '%s:\tfrom all%s\n' "\${pref:-32766}" "\$rest" >> "$W/iprules" ;;
  "rule del")
    shift 2; pat=""
    while [ \$# -gt 0 ]; do
      case "\$1" in
        pref)   shift 2 ;;
        # Matched the same way as on add: the real ip matches a rule by its
        # selectors, not by the text it happens to print.
        fwmark) pat="\$pat fwmark \$(printf '0x%x' "\$2")"; shift 2 ;;
        *)      pat="\$pat \$1"; shift ;;
      esac
    done
    grep -vF -- "\$pat" "$W/iprules" > "$W/iprules.n" 2>/dev/null
    mv "$W/iprules.n" "$W/iprules" ;;
  "rule list"|"rule show") cat "$W/iprules" ;;
  "route replace") shift 2; echo "\$*" >> "$W/iproutes" ;;
  "route flush")   : > "$W/iproutes" ;;
  "route show")    cat "$W/iproutes" 2>/dev/null ;;
esac
exit 0
IP

  # nft: records the ruleset it is handed, including rules fed on stdin.
  cat > "$W/bin/nft" <<NFT
#!/usr/bin/env bash
echo "nft \$*" >> "$W/calls"
[ "\$1" = "-f" ] && cat >> "$W/nft"
exit 0
NFT

  cat > "$W/bin/systemctl" <<SC
#!/usr/bin/env bash
echo "systemctl \$*" >> "$W/calls"
case "\$*" in
  *"is-active"*xray) [ "\$(cat "$W/xray-active" 2>/dev/null || echo yes)" = yes ] ;;
  *) exit 0 ;;
esac
SC

  cat > "$W/bin/logger" <<LG
#!/usr/bin/env bash
printf '%s\n' "\$*" >> "$W/log"
LG

  # curl: the two probes are told apart the way the script tells them apart —
  # by whether the request goes through the SOCKS inbound.
  cat > "$W/bin/curl" <<CURL
#!/usr/bin/env bash
kind=direct
for a in "\$@"; do [ "\$a" = "--socks5-hostname" ] && kind=socks; done
echo "curl \$kind" >> "$W/calls"
n=\$(( \$(cat "$W/curl-\$kind-n" 2>/dev/null || echo 0) + 1 ))
echo "\$n" > "$W/curl-\$kind-n"
[ "\$(cat "$W/probe-\$kind" 2>/dev/null || echo ok)" = ok ]
CURL

  # xray: only its stats API is used here, to answer "did the tunnel actually
  # receive bytes this cycle".
  cat > "$W/bin/xray" <<XR
#!/usr/bin/env bash
echo "xray \$*" >> "$W/calls"
b=\$(cat "$W/bytes" 2>/dev/null || echo "")
[ -z "\$b" ] && exit 1
cat <<J
{
  "stat": [
    {
      "name": "outbound>>>proxy>>>traffic>>>downlink",
      "value": "\$b"
    },
    {
      "name": "outbound>>>direct>>>traffic>>>downlink",
      "value": "99999999"
    }
  ]
}
J
XR

  cat > "$W/bin/ps" <<'PS'
#!/usr/bin/env bash
echo "  40960"
PS

  # sleep: the script deliberately waits between probe attempts and after
  # restarting tailscaled. Both are real behaviour worth keeping, and neither
  # is worth waiting for here.
  cat > "$W/bin/sleep" <<'SL'
#!/usr/bin/env bash
exit 0
SL

  # ts-bypass stand-in for the health tests: records the chain and action, and
  # can be made to fail so the "could not install the lifeline" path is
  # reachable. The real script has its own tests below.
  cat > "$W/lib/gateway/ts-bypass.sh" <<TS
#!/usr/bin/env bash
echo "ts-bypass \$*" >> "$W/calls"
[ -f "$W/ts-bypass-fails" ] && exit 1
exit 0
TS

  chmod +x "$W"/bin/* "$W/lib/gateway/ts-bypass.sh"
}

run_health() {
  ( export PATH="$W/bin:$PATH" GW_LIB="$W/lib/gateway" GW_STATE="$W/state" \
           GW_CONNTRACK="$W/netfilter"
    bash templates/lib/health.sh ) > "$W/out" 2>&1
}

run_iprules() {
  ( export PATH="$W/bin:$PATH" GW_LIB="$W/lib/gateway" GW_NET_CONF="$W/conf"
    sh templates/lib/ip-rules.sh "$@" ) > "$W/out" 2>&1
}

run_tsbypass() {
  ( export PATH="$W/bin:$PATH" GW_CGROUP="$W/cgroup"
    sh templates/lib/ts-bypass.sh "$@" ) > "$W/out" 2>&1
}

called()     { grep -qF -- "$1" "$W/calls"; }
logged()     { grep -qF -- "$1" "$W/log"; }
state()      { cat "$W/state/$1" 2>/dev/null; }
# The index of the first call matching a pattern, for ordering assertions.
call_at()    { grep -nF -- "$1" "$W/calls" | head -1 | cut -d: -f1; }

echo "== agent_test =="
echo
echo "  health.sh — the watchdog"

# -------------------------------------------------------- probe escalation --

# One timeout is not an outage. The failure path from here restarts Xray, which
# drops every live connection on every client, so a single lost packet — or a
# probe queued behind a client saturating the line — must not reach it.
# The first attempt fails, the second is allowed to succeed.
setup single-timeout
cat > "$W/bin/curl" <<CURL
#!/usr/bin/env bash
echo "curl" >> "$W/calls"
n=\$(( \$(cat "$W/n" 2>/dev/null || echo 0) + 1 )); echo "\$n" > "$W/n"
[ "\$n" -gt 1 ]
CURL
chmod +x "$W/bin/curl"
run_health
if [ "$(state tunnel)" = up ] && [ "$(cat "$W/n")" = 2 ]; then
  ok "a single failed probe is retried, not treated as an outage"
else
  bad "one timeout was enough to call the tunnel down (probes=$(cat "$W/n" 2>/dev/null), status=$(state tunnel))"
fi

setup both-fail
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
run_health
if [ "$(state tunnel)" = down ] && [ "$(state fails)" = 1 ]; then
  ok "two failed attempts count as one failed cycle"
else
  bad "status=$(state tunnel) fails=$(state fails) after both attempts failed"
fi

# The distinction that took an outage to learn: Xray and the tunnel can be
# perfectly healthy while the packets never reach them.
setup degraded
echo fail > "$W/probe-direct"; echo ok > "$W/probe-socks"
run_health
if [ "$(state tunnel)" = degraded ] && grep -q "prerouting" "$W/state/detail"; then
  ok "a tunnel that works over SOCKS but not intercepted is reported as degraded"
else
  bad "interception failure was reported as '$(state tunnel)', not degraded"
fi

if grep -q "INTERCEPTION BROKEN" "$W/log"; then
  ok "interception failure is logged at a different level from an outage"
else
  bad "a degraded gateway logged nothing distinguishable"
fi

# ----------------------------------------------------------- the restart --

setup restart-threshold
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 2 > "$W/state/fails"          # RESTART_AFTER is 3
run_health
if called "systemctl restart xray"; then
  ok "xray is restarted once the failure count reaches restart_after_fails"
else
  bad "the restart threshold was reached and nothing happened"
fi

setup restart-once
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 3 > "$W/state/fails"          # already past the threshold
run_health
if ! called "systemctl restart xray"; then
  ok "it restarts at the threshold, not on every cycle past it"
else
  bad "xray is restarted repeatedly while the tunnel stays down"
fi

# A restart is destructive, so evidence beats inference: if bytes arrived from
# the server during this very cycle the tunnel is carrying traffic, whatever
# the probe thinks, and restarting would manufacture the outage.
setup bytes-moving
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 2 > "$W/state/fails"
echo 500000 > "$W/state/bytes"
echo 900000 > "$W/bytes"
run_health
if ! called "systemctl restart xray"; then
  ok "a tunnel still receiving bytes is not restarted on a failed probe"
else
  bad "xray was restarted while the tunnel was actively receiving data"
fi
if logged "NOT restarting"; then
  ok "and it says why, so the probe URL gets suspected rather than the tunnel"
else
  bad "the skipped restart was silent"
fi

# The guard above is only as good as its evidence. Bytes on the direct
# outbound prove the box has internet, not that the tunnel does — counting them
# would suppress the restart in exactly the case that needs it.
setup bytes-direct-only
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 2 > "$W/state/fails"
echo 900000 > "$W/state/bytes"
echo 900000 > "$W/bytes"          # the tunnel received nothing; direct moved 99MB
run_health
if called "systemctl restart xray"; then
  ok "traffic on the direct outbound does not count as the tunnel working"
else
  bad "bytes that bypassed the tunnel were taken as proof the tunnel is fine"
fi

# The exception to that: if interception is broken, bytes moving proves only
# that some other path works. A restart is the right response.
setup bytes-moving-degraded
echo fail > "$W/probe-direct"; echo ok > "$W/probe-socks"
echo 2 > "$W/state/fails"
echo 500000 > "$W/state/bytes"
echo 900000 > "$W/bytes"
run_health
if called "systemctl restart xray"; then
  ok "a degraded gateway is restarted even while bytes move"
else
  bad "broken interception was excused by traffic on another path"
fi

# ------------------------------------------------------------- lifeline --

setup lifeline-early
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 8 > "$W/state/fails"       # 8 * 30s = 4m, under LIFELINE_MIN of 5
run_health
if ! called "ts-bypass lifeline on"; then
  ok "the lifeline waits out lifeline_after_min before engaging"
else
  bad "the lifeline engaged after $(( 8 * 30 ))s, under the 5m threshold"
fi

setup lifeline-engage
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 10 > "$W/state/fails"      # 10 * 30s = 5m
run_health
if called "ts-bypass lifeline on"; then
  ok "it engages once the tunnel has been down that long"
else
  bad "the lifeline never engaged"
fi
if [ "$(state lifeline)" = 1 ]; then
  ok "and records that it is engaged, so it is released on recovery"
else
  bad "the lifeline was engaged but not recorded"
fi

# nft resolves a cgroup path to an ID when the rule is inserted, and restarting
# tailscaled invalidates it. Adding the rule first would install one pointing
# at a cgroup that no longer exists — the failure mode is a lifeline that looks
# engaged and carries nothing.
if [ "$(call_at 'systemctl try-restart tailscaled')" -lt "$(call_at 'ts-bypass lifeline on')" ]; then
  ok "tailscaled is restarted before the rule is added, not after"
else
  bad "the cgroup rule was added before the restart that invalidates it"
fi

# The whole point of the lifeline is that it frees tailscaled and nothing else.
if ! grep -qE 'ts-bypass (exceptions|[a-z]+) on' "$W/calls" || \
   [ "$(grep -c 'ts-bypass' "$W/calls")" = "$(grep -c 'ts-bypass lifeline' "$W/calls")" ]; then
  ok "it opens the lifeline chain only — client traffic stays fail-closed"
else
  bad "the watchdog touched a chain other than lifeline: $(grep ts-bypass "$W/calls")"
fi

# A lifeline that could not be installed must not be recorded as engaged, or
# the next cycle skips the retry and the box is unreachable with the state file
# claiming otherwise.
setup lifeline-fails
echo fail > "$W/probe-direct"; echo fail > "$W/probe-socks"
echo 10 > "$W/state/fails"
touch "$W/ts-bypass-fails"
run_health
if [ "$(state lifeline)" != 1 ]; then
  ok "a lifeline that could not be installed is not recorded as engaged"
else
  bad "the lifeline was recorded as engaged after the rule failed to install"
fi
if logged "NOT engaged"; then
  ok "and says so loudly enough to recover from the console"
else
  bad "the failed lifeline was not reported"
fi

setup lifeline-release
echo 1 > "$W/state/lifeline"
echo 4 > "$W/state/fails"
run_health
if called "ts-bypass lifeline off" && [ "$(state lifeline)" = 0 ]; then
  ok "recovery releases the lifeline"
else
  bad "the lifeline survived the tunnel recovering"
fi
if [ "$(state fails)" = 0 ] && logged "healthy again"; then
  ok "and the failure count resets"
else
  bad "fails=$(state fails) after recovery"
fi

# ---------------------------------------------------------- observability --

# A full conntrack table drops NEW connections while leaving established ones
# alone, which on a client looks like the internet coming and going.
setup conntrack
echo 220000 > "$W/netfilter/nf_conntrack_count"   # 83% of 262144
run_health
if logged "conntrack"; then
  ok "a conntrack table nearing full is warned about before it fills"
else
  bad "conntrack at 83% passed without a word"
fi

# Intermittent faults are invisible to any live command: by the time anyone
# looks, the box is healthy again. The history is the only account of one.
setup history
run_health
if [ "$(wc -l < "$W/state/history")" = 1 ] && grep -q "ct=" "$W/state/history"; then
  ok "every probe appends a line to the history gw history reads back"
else
  bad "no usable history line was written"
fi

setup history-trim
# KEEP = 86400/30 + 60 = 2940; the trim fires above 2*KEEP.
yes "2020-01-01T00:00:00Z up ct=0/0 rss=0M load=0 rx=+0" | head -6000 > "$W/state/history"
run_health
if [ "$(wc -l < "$W/state/history")" -le 2941 ]; then
  ok "the history is trimmed, so a long-running box cannot fill tmpfs"
else
  bad "the history grew to $(wc -l < "$W/state/history") lines unchecked"
fi

setup xray-stopped
echo no > "$W/xray-active"
run_health
if [ "$(state tunnel)" = down ] && ! called "curl"; then
  ok "a stopped xray is reported without probing through it"
else
  bad "the probe ran against a service that is not running"
fi

echo
echo "  ip-rules.sh — policy routing"

setup iprules-up
run_iprules up
if grep -q "fwmark 0x1 lookup 100" "$W/iprules"; then
  ok "up installs the fwmark rule TPROXY delivery depends on"
else
  bad "no fwmark rule was added"
fi
if grep -q "local default dev lo table 100" "$W/iproutes" 2>/dev/null; then
  ok "and the local default route that makes the kernel deliver locally"
else
  bad "the route table was left empty: $(cat "$W/iproutes" 2>/dev/null)"
fi

# The effective value is max(all, <iface>), so zeroing the WAN interface alone
# is not enough — and tailscale0 appears after sysctl ran, inheriting `default`.
missed=""
for i in all lo eth0 tailscale0; do
  [ "$(cat "$W/conf/$i/rp_filter")" = 0 ] || missed="$missed $i"
done
if [ -z "$missed" ]; then
  ok "rp_filter is cleared on every interface, not just the WAN one"
else
  bad "rp_filter left set on:$missed — TPROXY packets die as martians there"
fi

missed=""
for i in all lo eth0 tailscale0; do
  [ "$(cat "$W/conf/$i/accept_local")" = 1 ] || missed="$missed $i"
done
if [ -z "$missed" ]; then
  ok "accept_local is set everywhere, so the reverse lookup is skipped outright"
else
  bad "accept_local left clear on:$missed"
fi

# Tailscale installs "from all lookup 52" at priority 5270. The LAN rule has to
# be ahead of it or the reverse-path lookup for a LAN client resolves via
# tailscale0 and the packet is dropped with no counter anywhere.
pref=$(grep "to 192.168.1.0/24" "$W/iprules" | cut -d: -f1)
if [ -n "$pref" ] && [ "$pref" -lt 5270 ]; then
  ok "the LAN reverse-path rule sits ahead of Tailscale's catch-all (pref $pref)"
else
  bad "the LAN rule is at pref '${pref:-none}', not ahead of Tailscale's 5270"
fi

before=$(wc -l < "$W/iprules")
run_iprules up
if [ "$(wc -l < "$W/iprules")" = "$before" ]; then
  ok "up is idempotent — a re-run adds no duplicate rules"
else
  bad "a second up added $(( $(wc -l < "$W/iprules") - before )) duplicate rule(s)"
fi

run_iprules down
if [ ! -s "$W/iprules" ] && [ ! -s "$W/iproutes" ]; then
  ok "down removes both rules and flushes the table"
else
  bad "down left rules behind: $(cat "$W/iprules")"
fi

setup iprules-down-clean
run_iprules down
if [ $? -eq 0 ]; then
  ok "down on a box that was never up still succeeds"
else
  bad "down failed when there was nothing to remove (exit $?)"
fi

setup iprules-usage
run_iprules sideways
if [ $? -eq 2 ]; then
  ok "an unknown argument exits 2 rather than doing something arbitrary"
else
  bad "'sideways' was accepted"
fi

echo
echo "  ts-bypass.sh — the only hole in a fail-closed firewall"

setup ts-no-cgroup
run_tsbypass lifeline on
rc=$?
if [ "$rc" != 0 ] && grep -q "cgroup not present" "$W/out"; then
  ok "on refuses when tailscaled's cgroup does not exist yet"
else
  bad "a rule was installed against a cgroup that is not there (exit $rc)"
fi
if [ ! -s "$W/nft" ]; then
  ok "and installs nothing, rather than a rule resolving to the wrong cgroup"
else
  bad "it wrote a ruleset anyway: $(cat "$W/nft")"
fi

setup ts-on
mkdir -p "$W/cgroup"
run_tsbypass lifeline on
if grep -q "socket cgroupv2 level 2 \"system.slice/tailscaled.service\" accept" "$W/nft"; then
  ok "on matches tailscaled by cgroup"
else
  bad "the installed rule was: $(cat "$W/nft")"
fi

# uid is useless (tailscaled runs as root, like AdGuard's DoH resolver and
# every other daemon) and daddr is useless (it talks to arbitrary DERP relays).
# Anything broader than the cgroup would free the whole box.
if ! grep -qE "skuid|daddr|tcp dport" "$W/nft"; then
  ok "and by nothing broader — no uid or address match to widen the hole"
else
  bad "the rule matches more than the cgroup: $(cat "$W/nft")"
fi

if grep -q "add rule inet gateway lifeline" "$W/nft"; then
  ok "the rule goes in the chain the caller named"
else
  bad "the chain was not the one requested: $(cat "$W/nft")"
fi

setup ts-exceptions
mkdir -p "$W/cgroup"
run_tsbypass exceptions on
if grep -q "add rule inet gateway exceptions" "$W/nft" && ! grep -q lifeline "$W/nft"; then
  ok "the permanent exception and the lifeline stay separate chains"
else
  bad "the two callers collided: $(cat "$W/nft")"
fi

# gw-health re-applies this every cycle while engaged, so a tailscaled restart
# self-heals. Without the flush that would accumulate a rule per cycle.
setup ts-idempotent
mkdir -p "$W/cgroup"
run_tsbypass lifeline on
if [ "$(call_at 'nft flush chain inet gateway lifeline')" -lt "$(call_at 'nft -f')" ]; then
  ok "the chain is flushed before the rule is added, so re-applying is safe"
else
  bad "a re-apply would stack duplicate rules"
fi

setup ts-off
mkdir -p "$W/cgroup"
run_tsbypass lifeline off
if called "nft flush chain inet gateway lifeline" && [ ! -s "$W/nft" ]; then
  ok "off flushes the chain and adds nothing back"
else
  bad "off did not close the hole: $(cat "$W/calls")"
fi

setup ts-usage
mkdir -p "$W/cgroup"
run_tsbypass lifeline sideways
if [ $? -eq 2 ] && [ ! -s "$W/nft" ]; then
  ok "an unknown action exits 2 without touching the ruleset"
else
  bad "'sideways' was accepted"
fi

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
