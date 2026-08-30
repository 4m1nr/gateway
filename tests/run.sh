#!/usr/bin/env bash
# Shell-side test suite. Runs anywhere — no gateway, no root, no network.
#
# The gateway is Go, and `go test ./...` owns everything about it: the config
# model, every generated file compared against frozen output and fed to a real
# `nft -c`, the firewall and routing invariants, the apply sequence, the
# dashboard's four gates. This file covers what is still shell — the ordered
# install scripts and the runtime helpers under templates/lib — plus the
# invariants that are about how those scripts are written rather than what they
# produce.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

echo "== the Go suite owns the rest =="
if command -v go >/dev/null 2>&1; then
  if go test -mod=vendor ./... >/tmp/gw-go-test.log 2>&1; then
    ok "go test ./... passed ($(grep -c '^ok' /tmp/gw-go-test.log) packages)"
  else
    bad "go test ./... failed:"
    tail -30 /tmp/gw-go-test.log | sed 's/^/      /'
  fi
else
  printf '  - go is not installed; skipping the Go suite\n'
fi

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

# The reverse lookup must resolve in main, ahead of Tailscale's catch-all rule
# at priority 5270, or validation can reject LAN clients as martians.
if grep -q 'ip rule add to "$LAN_CIDR" lookup main pref 90' templates/lib/ip-rules.sh; then
  ok "reverse-path lookups for the LAN are pinned to the main table"
else
  bad "no rule pinning LAN reverse-path lookups to main — another table can claim them"
fi

echo "== intermittent-fault evidence =="
# A fault that comes and go defeats every live command: by the time anyone runs
# `gw diag` the box is healthy again, and healthy is exactly what it reports.
# So the box has to record while it happens, and gw history has to read it back.
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
echo "== install scripts resolve through symlinks =="
# The scripts source lib/common.sh relative to themselves, which fails before
# common.sh can fix anything — so each one has to resolve $0 through symlinks
# first. This is exactly how it broke in the field.
LINKDIR=$(mktemp -d)
ln -sf "$PWD/scripts/40-web.sh" "$LINKDIR/websetup"
out=$("$LINKDIR/websetup" 2>&1 || true)
if printf '%s' "$out" | grep -q "common.sh: No such file"; then
  bad "a symlinked script cannot find lib/common.sh"
else
  ok "install scripts find lib/common.sh through a symlink"
fi
rm -rf "$LINKDIR"

echo
echo "== sbin tools are reachable regardless of the caller's PATH =="
# nft, sysctl and ip live in /usr/sbin, which is absent from some root PATHs.
# Calling them by bare name made `gw status` report "firewall not loaded"
# purely because it could not find nft, while `sudo gw apply` worked (sudo's
# secure_path includes /usr/sbin). The gw binary does the same thing in Go;
# TestEnsurePathAddsSbin covers that side.
for f in lib/common.sh templates/lib/net.sh; do
  if grep -q 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' "$f"; then
    ok "$(basename "$f") sets an explicit PATH"
  else
    bad "$(basename "$f") does not set PATH — sbin tools may be unreachable"
  fi
done

echo
echo "== awk programs actually parse =="
# `printf "%.1f", x>0 ? a : b` is a SYNTAX ERROR in awk: the > is parsed as
# output redirection. It fails silently inside a shell pipeline and produces
# empty output.
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

for f in templates/lib/*.sh scripts/*.sh; do
  if grep -nE '(printf|print)[^;]*,[^;]*[a-z0-9_]+ *> *[0-9]' "$f" | grep -v '(' >/dev/null 2>&1; then
    bad "$(basename "$f") has a print/printf with an unparenthesised > (awk reads it as redirection)"
  fi
done
ok "no unparenthesised > inside a print argument"


echo "== committed templates =="
# The README and .gitignore both point at these; losing them breaks a new
# install's starting point, and gitignore means git will not warn you.
if ! command -v jq >/dev/null 2>&1; then
  printf '  - jq is not installed; skipping the JSON validity check\n'
fi
for tpl in outbounds/main.example.json outbounds/work.example.json; do
  if [ ! -f "$tpl" ]; then bad "$tpl is missing"
  elif ! jq -e . "$tpl" >/dev/null 2>&1; then
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
for f in scripts/*.sh templates/lib/*.sh lib/common.sh; do
  if bash -n "$f" 2>/dev/null || sh -n "$f" 2>/dev/null; then ok "$(basename "$f")"
  else bad "$(basename "$f") has a syntax error"; fi
done

echo
echo "== every helper a script invokes is actually rendered =="
# scripts/20-adguard.sh called lib/agh_merge.py for a while after that file was
# deleted, and scripts/10-xray.sh called geoupdate.sh after it became Go. Both
# fail only when the script runs, which for an install script means on somebody
# else's first install.
if command -v go >/dev/null 2>&1 && [ -x bin/gw ]; then
  RENDER=$(mktemp -d)
  if GW_REPO="$PWD" ./bin/gw render --config tests/fixtures/default.toml --out "$RENDER" --quiet >/dev/null 2>&1; then
    dangling=""
    for ref in $(grep -rhoE '/usr/local/lib/gateway/[A-Za-z0-9_.-]+' scripts/ templates/ 2>/dev/null | sort -u); do
      name="${ref##*/}"
      # env and jobs/ are written by apply, not by the renderer's helper list;
      # gw-action is a copy of the binary.
      case "$name" in env|jobs|gw-action) continue ;; esac
      [ -e "$RENDER/usr/local/lib/gateway/$name" ] || dangling="$dangling $name"
    done
    if [ -z "$dangling" ]; then
      ok "every /usr/local/lib/gateway helper referenced by a script is rendered"
    else
      bad "scripts reference helpers that are never rendered:$dangling"
    fi

    missing=""
    for ref in $(grep -rhoE '\$REPO/[A-Za-z0-9_./-]+' scripts/ 2>/dev/null | sort -u); do
      path="${ref#\$REPO/}"
      case "$path" in *'$'*|*'{'*|build/*|gateway.toml) continue ;; esac
      [ -e "$path" ] || missing="$missing $path"
    done
    if [ -z "$missing" ]; then
      ok "every repo file referenced by a script exists"
    else
      bad "scripts reference files that do not exist:$missing"
    fi
  else
    bad "could not render to check script references"
  fi
  rm -rf "$RENDER"
else
  printf '  - gw is not built; skipping the reference check\n'
fi

echo
echo "== the bootstrap proxy is skipped once the tunnel is up =="
# The proxy exists for fetching things before the tunnel can carry them. Using
# it afterwards sends the download out through a tunnel already carrying it.
if grep -q 'gw_tunnel_is_up' templates/lib/net.sh; then
  ok "net.sh checks the tunnel before using the configured proxy"
else
  bad "net.sh uses BOOTSTRAP_PROXY regardless of whether the tunnel is up"
fi
if sed -n '/^gw_proxy()/,/^}/p' templates/lib/net.sh | grep -q 'GW_PROXY'; then
  ok "an explicit GW_PROXY override still wins"
else
  bad "gw_proxy no longer honours an explicit override"
fi

echo
echo "== no Python is left in the gateway =="
# The point of the migration: a box with no working internet cannot
# pip-install anything, and a stdlib-only Python was the previous answer to
# that. A .py file reappearing here means something reached for the old one.
stray=$(find bin lib scripts templates cmd internal -name '*.py' 2>/dev/null)
if [ -z "$stray" ]; then
  ok "no .py files anywhere in the gateway"
else
  bad "Python has come back: $stray"
fi

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
