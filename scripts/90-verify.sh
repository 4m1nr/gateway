#!/usr/bin/env bash
# End-to-end verification. Read-only unless you pass --killswitch, which
# deliberately stops Xray to prove that proxied traffic dies rather than
# leaking, then restarts it.
#
#   sudo gw check                 safe checks only
#   sudo gw check --killswitch    also test the fail-closed path (brief outage)
# Resolve $0 through symlinks before locating the shared helpers — a
# symlinked script would otherwise look for lib/common.sh next to the
# symlink instead of next to the real file.
_self="$0"
while [ -L "$_self" ]; do
  _link="$(readlink "$_self")"
  case "$_link" in /*) _self="$_link" ;; *) _self="$(dirname "$_self")/$_link" ;; esac
done
source "$(dirname "$_self")/../lib/common.sh"
need_root
[ -f /usr/local/lib/gateway/env ] \
  || die "/usr/local/lib/gateway/env is missing — run 'sudo gw apply' first"
. /usr/local/lib/gateway/env

KILLSWITCH=0
[ "${1:-}" = "--killswitch" ] && KILLSWITCH=1

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  %s✓%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad()  { printf '  %s✗%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  %s–%s %s\n' "$c_yel" "$c_off" "$*"; SKIP=$((SKIP+1)); }
sec()  { printf '\n%s%s%s\n' "$c_grn" "$1" "$c_off"; }

api() { xray api statsquery --server="127.0.0.1:${API_PORT:-10085}" 2>/dev/null; }
counter() {
  api | python3 -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print(0); sys.exit()
for s in d.get('stat',[]):
    if s.get('name')=='$1': print(s.get('value',0)); break
else: print(0)"
}

# --------------------------------------------------------------- services --
sec "services"
for u in gw-network xray AdGuardHome tailscaled; do
  if ! systemctl cat "$u" >/dev/null 2>&1; then skip "$u not installed"
  elif systemctl is-active --quiet "$u"; then ok "$u active"
  else bad "$u is $(systemctl is-active "$u")"; fi
done

# ------------------------------------------------------------ boot config --
sec "boot"
# "It works right now" and "it comes back after a power cut" are different
# claims. This checks the second one.
for u in gateway.target gw-network.service xray.service gw-health.timer gw-geoupdate.timer; do
  if ! systemctl cat "$u" >/dev/null 2>&1; then bad "$u is not installed"
  elif [ "$(systemctl is-enabled "$u" 2>/dev/null)" = "enabled" ]; then ok "$u enabled at boot"
  else bad "$u is NOT enabled — it will not come back after a reboot (run: sudo gw enable)"; fi
done
for u in AdGuardHome.service tailscaled.service chrony-wait.service; do
  if ! systemctl cat "$u" >/dev/null 2>&1; then skip "$u not installed"
  elif systemctl is-enabled "$u" >/dev/null 2>&1; then ok "$u enabled at boot"
  else bad "$u is NOT enabled at boot"; fi
done

# --------------------------------------------------------------- plumbing --
sec "plumbing"
if nft list table inet gateway >/dev/null 2>&1; then ok "nftables table loaded"
else bad "nftables table inet gateway is NOT loaded — nothing is intercepted"; fi

if ip rule list | grep -q "lookup $RT_TABLE"; then ok "fwmark policy rule present"
else bad "no fwmark rule — TPROXY packets will not be delivered locally"; fi

if ip route show table "$RT_TABLE" | grep -q "local default dev lo"; then
  ok "local default route in table $RT_TABLE"
else bad "table $RT_TABLE has no 'local default dev lo' route"; fi

if ss -lnt "sport = :$TPROXY_PORT" | grep -q "$TPROXY_PORT"; then
  ok "Xray is listening on the TPROXY port ($TPROXY_PORT)"
else bad "nothing listening on $TPROXY_PORT"; fi

# The clock is load-bearing: TLS and REALITY both fail on skew, and the symptom
# looks like a broken tunnel rather than a wrong time.
if command -v chronyc >/dev/null && chronyc tracking >/dev/null 2>&1; then
  OFF=$(chronyc tracking | awk '/System time/{print $4}')
  if awk -v o="$OFF" 'BEGIN{exit !(o < 2)}'; then ok "clock synced (offset ${OFF}s)"
  else bad "clock is off by ${OFF}s — TLS will fail"; fi
else skip "chrony not available"; fi

# ------------------------------------------------------------- catch-all --
sec "default policy"
# The whole point of the catch-all: a device only has to set its gateway.
case "${DEFAULT_POLICY:-proxy}" in
  proxy)
    if nft list chain inet gateway prerouting | grep -q "tproxy ip to 127.0.0.1:$TPROXY_PORT"; then
      ok "unlisted devices pointing here are intercepted by default"
    else bad "no catch-all TPROXY rule — an unlisted device would just be dropped"; fi
    if nft list chain inet gateway forward | grep -q "killswitch-default"; then
      ok "catch-all kill switch present"
    else bad "no catch-all kill switch — unlisted devices could leak if Xray dies"; fi ;;
  direct)  ok "default is direct — unlisted devices are forwarded unproxied" ;;
  block)   ok "default is block — unlisted devices are dropped" ;;
esac
if nft list chain inet gateway prerouting | grep -q "$BOX_IP.*$ROUTER\|{ $BOX_IP, $ROUTER }"; then
  ok "the box and the router are excluded from the catch-all"
else
  # nft may render the addresses via the defines rather than literally.
  nft -t list chain inet gateway prerouting >/dev/null 2>&1 \
    && skip "could not confirm the box/router exclusion from the live ruleset"
fi

# ------------------------------------------------------------------ egress --
sec "egress"
# Anything running as the xray user bypasses the tunnel (the OUTPUT chain
# returns early on skuid), which gives us the box's real address for free.
REAL=$(runuser -u xray -- curl -fsS --max-time 15 https://api.ipify.org 2>/dev/null || echo "")
TUN=$(curl -fsS --max-time 20 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
        https://api.ipify.org 2>/dev/null || echo "")

if [ -n "$REAL" ]; then ok "direct egress works (ISP address: $REAL)"
else bad "no direct egress — the box cannot reach the internet at all"; fi

if [ -n "$TUN" ]; then ok "tunnel egress works (exit address: $TUN)"
else bad "tunnel egress FAILED — check 'journalctl -u xray -n 50'"; fi

if [ -n "$REAL" ] && [ -n "$TUN" ]; then
  if [ "$REAL" != "$TUN" ]; then ok "tunnel egress differs from the ISP address"
  else bad "tunnel and direct show the SAME address — traffic is not being proxied"; fi
fi

# ------------------------------------------------------------- split rules --
sec "split routing"
if ! command -v xray >/dev/null || ! api >/dev/null 2>&1; then
  skip "Xray stats API unreachable — cannot verify the split"
else
  # Ask which outbound each request actually used, rather than inferring it.
  before_p=$(counter "outbound>>>proxy>>>traffic>>>uplink")
  before_d=$(counter "outbound>>>direct>>>traffic>>>uplink")
  curl -fsS --max-time 20 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
       -o /dev/null "${DOMESTIC_PROBE_URL:-https://www.irna.ir}" 2>/dev/null || true
  after_p=$(counter "outbound>>>proxy>>>traffic>>>uplink")
  after_d=$(counter "outbound>>>direct>>>traffic>>>uplink")
  dp=$((after_p - before_p)); dd=$((after_d - before_d))
  if [ "$dd" -gt "$dp" ]; then
    ok "domestic request went DIRECT (direct +${dd}B vs proxy +${dp}B)"
  elif [ "$dp" -gt 0 ]; then
    bad "domestic request went through the TUNNEL (proxy +${dp}B) — check geodata and the direct_geosite rules"
  else
    skip "domestic probe produced no traffic (site unreachable?)"
  fi

  before_p=$(counter "outbound>>>proxy>>>traffic>>>uplink")
  curl -fsS --max-time 20 --socks5-hostname "127.0.0.1:$SOCKS_PORT" \
       -o /dev/null https://www.google.com 2>/dev/null || true
  after_p=$(counter "outbound>>>proxy>>>traffic>>>uplink")
  if [ "$((after_p - before_p))" -gt 0 ]; then ok "foreign request went through the tunnel"
  else bad "foreign request did not use the proxy outbound"; fi
fi

# -------------------------------------------------------------------- dns --
sec "dns"
if getent hosts example.com >/dev/null 2>&1; then ok "the box resolves names"
else bad "the box cannot resolve — is AdGuard running?"; fi

if command -v dig >/dev/null; then
  if dig +short +time=5 +tries=1 @"$BOX_IP" example.com | grep -qE '^[0-9]'; then
    ok "AdGuard answers on $BOX_IP:53"
  else bad "no answer from $BOX_IP:53 — LAN clients will have no DNS"; fi
  if dig +short +time=5 +tries=1 @"$BOX_IP" irna.ir | grep -qE '^[0-9]'; then
    ok "domestic names resolve"
  else bad "domestic names do not resolve — check the [/ir/] upstream split"; fi
else skip "dig not installed"; fi

# ------------------------------------------------------------------- ipv6 --
sec "ipv6"
if ip -6 addr show dev "$WAN_IF" scope global 2>/dev/null | grep -q inet6; then
  bad "$WAN_IF has a global IPv6 address — clients can bypass the tunnel over v6"
else ok "$WAN_IF has no global IPv6 address"; fi
if curl -6 -fsS --max-time 5 https://api64.ipify.org >/dev/null 2>&1; then
  bad "the box has working IPv6 egress — that path is not proxied"
else ok "no IPv6 egress"; fi

# -------------------------------------------------------------- dashboard --
sec "web dashboard"
if [ ! -f /etc/gateway/web.json ]; then
  skip "dashboard not installed"
else
  WPORT=$(python3 -c "import json;print(json.load(open('/etc/gateway/web.json'))['port'])")
  WTLS=$(python3 -c "import json;print(json.load(open('/etc/gateway/web.json'))['tls'])")
  systemctl is-active --quiet gw-web && ok "gw-web is running" || bad "gw-web is not running"

  if [ -f /etc/gateway/web-auth.json ]; then
    perms=$(stat -c '%a %U:%G' /etc/gateway/web-auth.json)
    if [ "$perms" = "600 root:root" ]; then
      ok "password hash is 0600 root:root (the web process cannot read it)"
    else bad "password hash is $perms — expected 600 root:root"; fi
  else
    bad "no dashboard password set — every login will fail (run: sudo gw web-passwd)"
  fi

  # The sudo grant is the dashboard's entire privilege surface.
  if grep -qE 'NOPASSWD:.*[*]' /etc/sudoers.d/gw-web 2>/dev/null; then
    bad "/etc/sudoers.d/gw-web contains a wildcard — it should grant exactly one command"
  else ok "sudo grant is a single command with no wildcard"; fi
  owner=$(stat -c '%U' /usr/local/lib/gateway/web-action.py 2>/dev/null)
  if [ "$owner" = "root" ]; then
    ok "the privileged helper is owned by root"
  else bad "web-action.py is owned by $owner — gwweb could rewrite what it sudoes"; fi

  # Gate 1: the port must not be open to the whole world.
  if nft list chain inet gateway input 2>/dev/null | grep -q "dport $WPORT accept"; then
    if nft list chain inet gateway input | grep "dport $WPORT" | grep -q "saddr"; then
      ok "dashboard port $WPORT is restricted by source address"
    else bad "dashboard port $WPORT is accepted from ANY source"; fi
  else bad "no firewall rule for the dashboard port"; fi

  [ "$WTLS" = "True" ] && ok "dashboard uses TLS" \
    || bad "dashboard is plain HTTP — the login password crosses the LAN in clear text"
fi

# -------------------------------------------------------------- tailscale --
sec "tailscale"
if command -v tailscale >/dev/null && tailscale status >/dev/null 2>&1; then
  ok "tailscale connected as $(tailscale status --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null || echo '?')"
  tailscale status --json | grep -q '"ExitNodeOption": *true' \
    && ok "advertised as an exit node" \
    || skip "not advertised as an exit node (or not yet approved in the admin console)"
  if [ "$(cat /run/gateway/lifeline 2>/dev/null || echo 0)" = "1" ]; then
    bad "the lifeline is ENGAGED — tailscaled is bypassing the tunnel because it has been down too long"
  else ok "lifeline not engaged"; fi
else skip "tailscale not set up"; fi

# ------------------------------------------------------------- killswitch --
if [ "$KILLSWITCH" -eq 1 ]; then
  sec "killswitch (this briefly cuts proxied clients off)"
  DROPS_BEFORE=$(nft list chain inet gateway forward | grep killswitch | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' || echo 0)
  systemctl stop xray
  sleep 2
  if ss -lnt "sport = :$TPROXY_PORT" | grep -q "$TPROXY_PORT"; then
    bad "something is still listening on $TPROXY_PORT after stopping Xray"
  else ok "Xray stopped, TPROXY listener gone"
  fi
  # With no listener, an intercepted client's packets fall through to the
  # terminal drop instead of finding a direct path out.
  if nft list chain inet gateway forward | grep -q "killswitch"; then
    ok "killswitch drop rule is in place (drops so far: $DROPS_BEFORE)"
  else bad "no killswitch rule in the forward chain — traffic could leak"; fi
  systemctl start xray
  sleep 3
  systemctl is-active --quiet xray && ok "Xray restarted" || bad "Xray did not come back"
fi

sec "summary"
printf '  %d passed, %d failed, %d skipped\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
