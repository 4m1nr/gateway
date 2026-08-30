#!/usr/bin/env bash
# Behavioural tests for bootstrap-proxy resolution.
#
# There are two implementations of one rule — lib/common.sh for the install
# scripts and templates/lib/net.sh for the runtime helpers — and they have to
# agree. Grepping for a function name proves neither of them works, so this
# sources each and calls gw_proxy for real, across every combination that
# matters.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# ask <implementation> <tunnel-state> <config-proxy> <env-proxy> <GW_PROXY>
#
# Runs gw_proxy in a subshell with exactly those conditions and prints what it
# chose. Each implementation reads its inputs differently — common.sh parses
# gateway.toml, net.sh takes BOOTSTRAP_PROXY from the sourced env file — so both
# are supplied and each takes what it uses.
ask() {
  local impl="$1" tunnel="$2" config_proxy="$3" env_proxy="$4" override="$5"

  local run="$WORK/run"; rm -rf "$run"; mkdir -p "$run/gateway"
  [ "$tunnel" != "none" ] && printf '%s' "$tunnel" > "$run/gateway/tunnel"

  local cfg="$WORK/gateway.toml"
  if [ "$config_proxy" = "none" ]; then
    rm -f "$cfg"
  else
    printf '[bootstrap]\nsocks_proxy = "%s"\n\n[net]\nwan_if = "eth0"\n' "$config_proxy" > "$cfg"
  fi

  (
    # Both implementations read the tunnel state from a fixed path, so the test
    # substitutes it by overriding the reader rather than by writing to /run.
    case "$impl" in
      common)
        CONFIG="$cfg"
        # shellcheck disable=SC1091
        source lib/common.sh 2>/dev/null || true
        CONFIG="$cfg"
        ;;
      net)
        BOOTSTRAP_PROXY="$env_proxy"
        [ "$env_proxy" = "none" ] && BOOTSTRAP_PROXY=""
        # shellcheck disable=SC1091
        source templates/lib/net.sh 2>/dev/null || true
        ;;
    esac

    # Redefine the state reader to point at this run's directory. Both files
    # define gw_tunnel_is_up, so overriding it here is the seam.
    gw_tunnel_is_up() { [ "$(cat "$run/gateway/tunnel" 2>/dev/null || true)" = "up" ]; }

    if [ "$override" = "none" ]; then unset GW_PROXY; else export GW_PROXY="$override"; fi
    gw_proxy
  )
}

# expect <label> <expected> <impl> <tunnel> <config> <env> <override>
expect() {
  local label="$1" want="$2"; shift 2
  local got; got=$(ask "$@")
  [ "$want" = "empty" ] && want=""
  if [ "$got" = "$want" ]; then
    ok "$label"
  else
    bad "$label — got '${got:-<empty>}', want '${want:-<empty>}'"
  fi
}

P="socks5h://127.0.0.1:1080"
O="http://override:3128"

echo "== the proxy is used while the tunnel cannot carry the download =="
for state in down degraded unknown none; do
  expect "common.sh, tunnel $state"  "$P" common "$state" "$P" "$P" none
  expect "net.sh, tunnel $state"     "$P" net    "$state" "$P" "$P" none
done

echo
echo "== and is skipped once it can =="
# This is the whole point: afterwards the box's own traffic already goes
# through Xray, so the proxy would send it out through a tunnel already
# carrying it — and fails outright once the proxy is gone.
expect "common.sh, tunnel up" empty common up "$P" "$P" none
expect "net.sh, tunnel up"    empty net    up "$P" "$P" none

echo
echo "== an explicit override always wins =="
# Someone passing --proxy has said what they want; inferring around that would
# be worse than obeying it.
expect "common.sh, override with the tunnel up"   "$O" common up   "$P"  "$P"  "$O"
expect "net.sh, override with the tunnel up"      "$O" net    up   "$P"  "$P"  "$O"
expect "common.sh, override with nothing else"    "$O" common down none none  "$O"
expect "net.sh, override with nothing else"       "$O" net    down none none  "$O"

echo
echo "== no proxy configured means no proxy =="
for state in up down none; do
  expect "common.sh, nothing set, tunnel $state" empty common "$state" none none none
  expect "net.sh, nothing set, tunnel $state"    empty net    "$state" none none none
done

echo
echo "== a first install has no config to read =="
# 00-bootstrap.sh runs before `gw init`, so gateway.toml does not exist yet.
# gw_proxy must return empty quietly rather than erroring on the missing file —
# and GW_PROXY must still work, because it is the only route a proxied first
# install has.
missing_output=$( (
  CONFIG="$WORK/definitely-absent.toml"
  source lib/common.sh 2>&1 >/dev/null || true
  CONFIG="$WORK/definitely-absent.toml"
  gw_proxy >/dev/null
) 2>&1 )
if [ -z "$missing_output" ]; then
  ok "common.sh is silent when gateway.toml does not exist yet"
else
  bad "common.sh writes to stderr with no config: $missing_output"
fi
expect "common.sh, first install with GW_PROXY" "$O" common none none none "$O"

echo
echo "== the two implementations agree =="
# One rule, two languages. A difference here means an install script and a
# runtime helper disagree about whether to use the proxy, which is the kind of
# thing nobody notices until a download fails on one path only.
disagreements=0
for state in up down degraded none; do
  for cfg in "$P" none; do
    for ovr in "$O" none; do
      a=$(ask common "$state" "$cfg" "$cfg" "$ovr")
      b=$(ask net    "$state" "$cfg" "$cfg" "$ovr")
      if [ "$a" != "$b" ]; then
        bad "tunnel=$state config=$cfg override=$ovr: common.sh says '$a', net.sh says '$b'"
        disagreements=$((disagreements + 1))
      fi
    done
  done
done
[ "$disagreements" -eq 0 ] && ok "common.sh and net.sh agree in all 16 combinations"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
