#!/usr/bin/env bash
# What the shipped scripts depend on.
#
# The gateway builds and runs with the distro's Go and nothing else — no
# interpreter to install, nothing to fetch on a box whose network is the thing
# being repaired. Two ways that quietly stops being true: a script reaches for
# an interpreter again, or it calls a tool bootstrap does not install.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

SHIPPED="scripts/*.sh templates/lib/*.sh lib/common.sh"

echo "== no interpreter is invoked anywhere =="
# awk is not on this list: it is in the base system and used deliberately.
#
# Matching an invocation, not a mention. Several of these files legitimately
# discuss Python having been removed, and 30-tailscale.sh tells you to approve
# the machine as an exit *node* — so a name only counts when followed by what
# an invocation is followed by: a flag, a path, a quote, or a variable.
for interp in python python2 python3 perl ruby node nodejs php; do
  hits=$(grep -nE "(^|[|;&(\`]|\\\$\(|exec )[[:space:]]*${interp}[0-9]*[[:space:]]+[-/\"'\$]" \
         $SHIPPED 2>/dev/null || true)
  if [ -z "$hits" ]; then
    ok "no $interp"
  else
    bad "$interp is invoked by a shipped script:"
    printf '%s\n' "$hits" | sed 's/^/      /'
  fi
done

echo
echo "== no script has an interpreter shebang =="
for f in $SHIPPED; do
  [ -e "$f" ] || continue
  case "$(head -1 "$f")" in
    '#!'*python*|'#!'*perl*|'#!'*node*|'#!'*ruby*)
      bad "$(basename "$f"): $(head -1 "$f")" ;;
  esac
done
ok "every shipped script is shell"

echo
echo "== every tool the scripts need comes from a package bootstrap installs =="
# Read out of 00-bootstrap.sh rather than restated here: a second copy would
# drift and then cheerfully agree with itself.
# awk rather than a grep alternation: an empty branch like (a|b|)$ is accepted
# by GNU grep and rejected by stricter engines, and a test that only runs on one
# grep is not much of a test.
PACKAGES=$(sed -n '/apt-get install -y --no-install-recommends/,/^$/p' scripts/00-bootstrap.sh \
           | tr ' \\' '\n\n' \
           | awk 'NF && $0 !~ /^(apt-get|install|-y|--no-install-recommends)$/' \
           | tr '\n' ' ' || true)

# Curated deliberately. Extracting every word from a shell script reports mostly
# prose, and a check whose output nobody reads is one nobody acts on. These are
# the tools whose absence actually breaks something, with what breaks.
# The corpus to search for invocations, with bootstrap's own package list
# removed. Without that removal the check is self-referential: `ethtool` appears
# in the list of packages to install, the grep matches it there, and deleting
# the package makes the check vanish instead of fail — which is exactly what it
# did the first time it was tried against a deliberate regression.
CORPUS=$(mktemp); trap 'rm -f "$CORPUS"' EXIT
for f in $SHIPPED; do
  [ -e "$f" ] || continue
  case "$f" in
    # Only bootstrap's list is stripped. Other scripts install a package too —
    # 40-web.sh pulls in openssl when it is missing — and deleting their blocks
    # as well hid the very calls this is meant to find.
    */00-bootstrap.sh) sed '/apt-get install -y --no-install-recommends/,/^$/d' "$f" >> "$CORPUS" ;;
    *) cat "$f" >> "$CORPUS" ;;
  esac
done

check_dep() {
  local cmd="$1" pkg="$2" why="$3"
  if ! grep -qE "(^|[|;&(\`]|\\\$\()[[:space:]]*${cmd}([[:space:]]|\$)" "$CORPUS" 2>/dev/null; then
    printf '  – %s is not called by any shipped script (Go owns it now)\n' "$cmd"
    return 0
  fi
  case " $PACKAGES " in
    *" $pkg "*) ok "$cmd <- $pkg" ;;
    *) bad "the scripts call $cmd but bootstrap does not install $pkg — $why" ;;
  esac
}
check_dep nft     nftables   "the firewall is never loaded"
check_dep curl    curl       "nothing can be downloaded"
check_dep jq      jq         "release metadata cannot be read"
check_dep unzip   unzip      "the Xray release cannot be unpacked"
check_dep chronyc chrony     "clock skew goes unnoticed, and TLS fails on it"
check_dep openssl openssl    "the dashboard has no certificate"
check_dep visudo  sudo       "the sudoers fragment is installed unvalidated"
check_dep setpriv util-linux "the direct-egress test cannot drop privileges"
check_dep nsenter util-linux "the privileged helper cannot leave its sandbox"
check_dep go      golang-go  "gw cannot be built at all"
check_dep dig     dnsutils   "gw check cannot verify DNS"
check_dep ethtool ethtool    "link speed is unreadable in gw bench"

echo
echo "== bootstrap installs no runtime it no longer needs =="
if grep -qE '^\s+.*\bpython3(-[a-z]+)?\b' scripts/00-bootstrap.sh; then
  bad "00-bootstrap.sh installs python3 again — something is depending on it"
else
  ok "no Python runtime is installed"
fi

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
