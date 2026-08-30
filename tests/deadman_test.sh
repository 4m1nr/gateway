#!/usr/bin/env bash
# Behavioural tests for the dead-man switch.
#
# This is the one script in the repo that runs unattended, as root, on a box
# nobody can reach, at the exact moment everything else has gone wrong. It gets
# no second try and nobody watches it fail. So these tests run the real
# functions against a scratch root with the system commands stubbed, and check
# what actually happened to the filesystem — not that the right command was
# spelled.
#
# Two things are deliberately over-covered, because both were real bugs caught
# only by running it: `systemctl is-enabled` exits non-zero for a unit that does
# not exist, which under `set -euo pipefail` aborted the snapshot partway
# through; and a unit recorded as `disabled` has to be UNMASKED on restore,
# because bootstrap masks nftables.service.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
DEADMAN="$PWD/scripts/deadman.sh"

# --------------------------------------------------------------- the harness --
# The script is a program, not a library: sourcing it runs its dispatcher. So
# the harness sets $0 (which is what `arm` hands to systemd-run), neutralises
# the dispatcher with a harmless subcommand, sources the script, and only then
# replaces need_root and every system command with stubs that trace to a file.
#
# Tracing to a file rather than stdout is not a style choice: restore redirects
# all of these to /dev/null on purpose, so a stub that printed would show
# nothing.
write_harness() {
  cat > "$WORK/harness.sh" <<'HARNESS'
BASH_ARGV0="$DM_SCRIPT"
# Save what we were asked to run BEFORE neutralising the dispatcher: `set --`
# replaces the positional parameters, so "$@" at the bottom would otherwise be
# the placeholder rather than the function under test.
DM_CALL=("$@")
set -- status                      # dispatcher runs do_status: needs no root
# shellcheck disable=SC1090
source "$DM_SCRIPT" >/dev/null 2>&1
need_root() { :; }

# systemctl answers is-enabled/is-active from a fixture describing the machine
# BEFORE the install, and traces everything else.
systemctl() {
  case "${1:-}" in
    is-enabled|is-active)
      # Faithful to real systemd, which is the whole point of the fixture: for a
      # unit that does not exist, is-enabled prints "not-found" and exits 4,
      # while is-active prints "inactive" and exits 3. They disagree, and a stub
      # that made them agree would quietly skip the branch that handles it.
      local state
      state=$(awk -v u="${2:-}" -v q="$1" \
        '$1==u { print (q=="is-enabled" ? $2 : $3) }' "$DM_UNITSTATE" 2>/dev/null)
      [ -n "$state" ] || return 1
      if [ "$1" = "is-enabled" ] && [ "$state" = "notfound" ]; then
        echo "not-found"; return 4
      fi
      echo "$state"
      [ "$state" = "inactive" ] && return 3
      return 0 ;;
    list-timers) return 1 ;;
  esac
  echo "systemctl $*" >> "$DM_TRACE"
}
nft()        { echo "nft $*"        >> "$DM_TRACE"; }
ip()         { echo "ip $*"         >> "$DM_TRACE"; }
sysctl()     { echo "sysctl $*"     >> "$DM_TRACE"; }
systemd-run() { echo "systemd-run $*" >> "$DM_TRACE"; }
ping()       { echo "ping $*"       >> "$DM_TRACE"; return "${DM_PING_RC:-1}"; }
sleep()      { :; }
"${DM_CALL[@]}"
HARNESS
}
write_harness

# harness <units-fixture> <function> [args...] — run one function in a subshell
harness() {
  local fixture="$1"; shift
  DM_SCRIPT="$DEADMAN" DM_UNITSTATE="$fixture" DM_TRACE="$TRACE" \
  DM_PING_RC="${PING_RC:-1}" \
  GW_DEADMAN_STATE="$STATE" GW_DEADMAN_LOG="$WORK/log" GW_ROOT="$ROOT" \
    bash "$WORK/harness.sh" "$@"
}

# A fresh scratch root and state dir per test. Each one starts from the machine
# as it looks BEFORE the gateway is installed, which is what a snapshot has to
# capture and a restore has to reproduce.
fresh() {
  ROOT="$WORK/root";  rm -rf "$ROOT";  mkdir -p "$ROOT/etc/systemd/network" \
    "$ROOT/etc/sysctl.d" "$ROOT/usr/local/lib/gateway"
  STATE="$WORK/state"; rm -rf "$STATE"
  TRACE="$WORK/trace"; : > "$TRACE"
  printf 'nameserver 192.168.1.1\n' > "$ROOT/etc/resolv.conf"
}

# The pre-install machine: NetworkManager running, networkd off, nftables merely
# disabled (bootstrap is what masks it), and networking.service absent — which
# is the normal shape of a Debian box and the one that broke the snapshot.
UNITS_BEFORE="$WORK/units.before"
cat > "$UNITS_BEFORE" <<'FIXTURE'
NetworkManager.service enabled active
networking.service notfound inactive
systemd-networkd.service disabled inactive
systemd-networkd-wait-online.service disabled inactive
systemd-resolved.service enabled active
wpa_supplicant.service disabled inactive
nftables.service disabled inactive
FIXTURE

traced() { grep -qF "$1" "$TRACE"; }
# order <first> <second> — is the first traced line strictly before the second?
order() {
  local a b
  a=$(grep -nF "$1" "$TRACE" | head -1 | cut -d: -f1)
  b=$(grep -nF "$2" "$TRACE" | head -1 | cut -d: -f1)
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt "$b" ]
}

# ------------------------------------------------------------------ snapshot --
echo "== the snapshot survives units that do not exist =="
# `systemctl is-enabled networking.service` on a networkd box prints "not-found"
# AND exits 4. common.sh sets `set -euo pipefail`, so the assignment aborted the
# whole function — arming a timer over a half-written record, which is worse
# than no timer at all because you then trust it.
fresh
if harness "$UNITS_BEFORE" do_snapshot >/dev/null 2>&1; then
  ok "do_snapshot exits 0 with a not-found unit among the tracked set"
else
  bad "do_snapshot aborted on a not-found unit (set -e + is-enabled exit 4)"
fi

if [ -f "$STATE/units" ]; then
  want=$(wc -l < "$UNITS_BEFORE")
  got=$(wc -l < "$STATE/units")
  if [ "$got" -eq "$want" ]; then
    ok "one line per tracked unit ($got)"
  else
    bad "expected $want unit lines, got $got — the not-found fallback added a second line"
  fi
  if [ "$(awk 'NF!=3' "$STATE/units" | wc -l)" -eq 0 ]; then
    ok "every unit record has exactly three fields"
  else
    bad "malformed unit records:"; awk 'NF!=3' "$STATE/units" | sed 's/^/      /'
  fi
  if grep -q '^networking.service not-found' "$STATE/units"; then
    ok "a missing unit is recorded as not-found, on its own line"
  else
    bad "networking.service was not recorded as not-found:"
    sed 's/^/      /' "$STATE/units"
  fi
else
  bad "do_snapshot wrote no unit record at all"
fi

echo
echo "== the snapshot records how resolv.conf was configured =="
# A symlink into /run (systemd-resolved) restored as a plain copy is a stale
# resolver that outlives the rollback — the box comes back "working" and then
# cannot resolve anything the moment the lease changes.
fresh
ln -sfn ../run/systemd/resolve/stub-resolv.conf "$ROOT/etc/resolv.conf"
harness "$UNITS_BEFORE" do_snapshot >/dev/null 2>&1
if grep -q '^symlink ../run/systemd/resolve/stub-resolv.conf' "$STATE/resolv.kind" 2>/dev/null; then
  ok "a symlinked resolv.conf is recorded as a symlink, with its target"
else
  bad "symlinked resolv.conf recorded as: $(cat "$STATE/resolv.kind" 2>/dev/null)"
fi

fresh
harness "$UNITS_BEFORE" do_snapshot >/dev/null 2>&1
if [ "$(cat "$STATE/resolv.kind" 2>/dev/null)" = "file" ] && \
   grep -q 'nameserver 192.168.1.1' "$STATE/resolv.conf" 2>/dev/null; then
  ok "a real resolv.conf is copied, contents and all"
else
  bad "a plain resolv.conf was not snapshotted"
fi

fresh
rm -f "$ROOT/etc/resolv.conf"
if harness "$UNITS_BEFORE" do_snapshot >/dev/null 2>&1 &&
   [ "$(cat "$STATE/resolv.kind" 2>/dev/null)" = "absent" ]; then
  ok "no resolv.conf at all is recorded as absent, without failing"
else
  bad "a missing resolv.conf broke the snapshot"
fi

# ------------------------------------------------------------------- restore --
# Every restore test starts from a snapshot of the pre-install machine, then
# runs restore against a root that looks post-install.
post_install_root() {
  fresh
  harness "$UNITS_BEFORE" do_snapshot >/dev/null 2>&1
  : > "$ROOT/etc/systemd/network/10-gateway-wan.network"
  : > "$ROOT/etc/sysctl.d/99-gateway.conf"
  printf 'nameserver 127.0.0.1\n' > "$ROOT/etc/resolv.conf"   # AdGuard, now dead
  : > "$TRACE"
}

echo
echo "== restore removes the generated configuration =="
post_install_root
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
[ ! -e "$ROOT/etc/systemd/network/10-gateway-wan.network" ] \
  && ok "the generated .network file is gone" \
  || bad "10-gateway-wan.network survived the rollback — the box reboots into the static address"
[ ! -e "$ROOT/etc/sysctl.d/99-gateway.conf" ] \
  && ok "the gateway sysctl drop-in is gone" \
  || bad "99-gateway.conf survived the rollback"
grep -q 'nameserver 192.168.1.1' "$ROOT/etc/resolv.conf" 2>/dev/null \
  && ok "resolv.conf is back to what it was before the install" \
  || bad "resolv.conf still points somewhere else: $(cat "$ROOT/etc/resolv.conf" 2>/dev/null)"

echo
echo "== restore disables the gateway units, not just stops them =="
# gw-network.service is WantedBy=sysinit.target and the others are pulled in by
# gateway.target. Stopping alone lasts until the next reboot, which is the one
# thing the box is guaranteed to do while nobody can reach it.
post_install_root
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
missing=""
for u in gateway.target gw-network.service xray.service gw-health.timer \
         gw-geoupdate.timer gw-update.timer gw-web.service \
         gw-tailscale-exception.service; do
  traced "systemctl stop $u"    || missing="$missing stop:$u"
  traced "systemctl disable $u" || missing="$missing disable:$u"
done
[ -z "$missing" ] && ok "every gateway unit is stopped and disabled" \
                  || bad "not torn down:$missing"

echo
echo "== restore tears down interception before the routing that serves it =="
# Order is the property. Drop the policy routing first and marked packets are
# still being produced with nowhere to go; drop the table first and there is
# simply nothing left to intercept.
post_install_root
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
order "nft delete table inet gateway" "ip rule del fwmark 1 lookup 100" \
  && ok "the nft table goes before the fwmark rule" \
  || bad "policy routing is removed before the table that feeds it"
traced "nft delete table ip gwpanic" \
  && ok "a leftover panic-mode NAT table is removed too" \
  || bad "gw panic's table would survive the rollback"

echo
echo "== the policy routing is torn down even with no helper installed =="
# ip-rules.sh needs an env file that a half-finished install may never have
# written. If restore leaned on it alone, the fwmark rule would stay and divert
# everything to lo — a box that looks restored and has no network.
post_install_root
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1     # no ip-rules.sh in $ROOT
traced "ip rule del fwmark 1 lookup 100" && traced "ip route flush table 100" \
  && ok "the fwmark rule and table 100 are removed by hand as well" \
  || bad "the fwmark rule survives when ip-rules.sh is absent"

echo
echo "== restore hands the interface back in the right order =="
# Two managers on one interface is its own outage. networkd has to be stopped
# and the static address flushed before NetworkManager is started, or NM finds
# the link already configured and leaves it alone.
post_install_root
printf 'enp3s0\n' > "$STATE/wan_if"
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
order "systemctl stop systemd-networkd.socket" "ip addr flush dev enp3s0" \
  && ok "networkd is stopped before the address is flushed" \
  || bad "the address is flushed while networkd still owns the link"
order "ip addr flush dev enp3s0" "systemctl start NetworkManager.service" \
  && ok "the address is flushed before NetworkManager starts" \
  || bad "NetworkManager starts onto a link that still holds the static address"
order "systemctl enable NetworkManager.service" "systemctl start NetworkManager.service" \
  && ok "the enable pass completes before anything is started" \
  || bad "units are started during the enable pass"

echo
echo "== restore unmasks what it re-enables, and what it re-disables =="
# bootstrap MASKS nftables.service. A snapshot taken beforehand records it as
# merely `disabled`, and disabling a masked unit succeeds while leaving it
# masked — so without an unmask the box comes out of a rollback unable to start
# it at all.
post_install_root
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
traced "systemctl unmask nftables.service" \
  && ok "a unit recorded as disabled is unmasked, not just disabled" \
  || bad "nftables.service would stay masked after a rollback"
traced "systemctl unmask NetworkManager.service" \
  && ok "a unit recorded as enabled is unmasked before being enabled" \
  || bad "an enabled unit is not unmasked"

echo
echo "== restore leaves units it never knew about alone =="
# networking.service does not exist on a networkd box. Starting or stopping it
# is harmless but it is noise in the log of a rollback nobody watched, and the
# log is the only evidence of what happened.
post_install_root
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
if grep -E "systemctl (start|stop|enable|disable) networking.service" "$TRACE" >/dev/null; then
  bad "restore acted on networking.service, which does not exist"
else
  ok "a not-found unit is skipped entirely"
fi

echo
echo "== restore works with no snapshot at all =="
# Someone running `restore` by hand without arming first. Tearing the gateway
# down is still right; only the "put it back as it was" half has nothing to
# work from, and it must say so rather than crash.
fresh
: > "$ROOT/etc/systemd/network/10-gateway-wan.network"
if harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1; then
  ok "do_restore exits 0 with no snapshot"
else
  bad "do_restore failed when no snapshot existed"
fi
traced "nft delete table inet gateway" \
  && ok "it still tears the gateway down" \
  || bad "with no snapshot it did not even tear the gateway down"
[ ! -e "$ROOT/etc/systemd/network/10-gateway-wan.network" ] \
  && ok "it still removes the generated .network file" \
  || bad "the generated .network file survived"

echo
echo "== the reboot of last resort fires only on evidence =="
# GW_DEADMAN_REBOOT is opt-in and destructive. "I could not check" must never
# be treated as "it is broken": with no peer and no router recorded there is
# nothing to probe, and rebooting on that would be a guess.
post_install_root
printf '192.168.1.77\n' > "$STATE/peers"
GW_DEADMAN_REBOOT=1 harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
traced "systemctl reboot" \
  && ok "reboots when a recorded peer was probed and did not answer" \
  || bad "GW_DEADMAN_REBOOT=1 did not reboot after a failed probe"

post_install_root
rm -f "$STATE/peers" "$STATE/router"
GW_DEADMAN_REBOOT=1 harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
traced "systemctl reboot" \
  && bad "rebooted with nothing to probe — 'could not check' is not 'broken'" \
  || ok "does not reboot when there was nothing to probe"

post_install_root
printf '192.168.1.77\n' > "$STATE/peers"
PING_RC=0 GW_DEADMAN_REBOOT=1 harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
traced "systemctl reboot" \
  && bad "rebooted even though the peer answered" \
  || ok "does not reboot when the peer is reachable again"

post_install_root
printf '192.168.1.77\n' > "$STATE/peers"
harness "$UNITS_BEFORE" do_restore >/dev/null 2>&1
traced "systemctl reboot" \
  && bad "rebooted without GW_DEADMAN_REBOOT=1" \
  || ok "never reboots unless asked to"

# ----------------------------------------------------------------------- arm --
echo
echo "== arming keeps the snapshot it started with =="
# Re-arming between install steps is the intended workflow. Re-snapshotting on
# each one would faithfully record the half-broken configuration and then
# restore THAT — the failure mode where the safety net hands you the thing you
# were trying to escape.
post_install_root
before=$(cat "$STATE/units")
harness "$UNITS_BEFORE" do_arm 10m >/dev/null 2>&1
after=$(cat "$STATE/units")
[ "$before" = "$after" ] \
  && ok "re-arming does not overwrite the original snapshot" \
  || bad "re-arming re-snapshotted the post-install state"
grep -q 'nameserver 192.168.1.1' "$STATE/resolv.conf" \
  && ok "the kept snapshot still holds the pre-install resolver" \
  || bad "the snapshot now holds the gateway's own resolver"

echo
echo "== arming with no snapshot takes one =="
fresh
harness "$UNITS_BEFORE" do_arm 10m >/dev/null 2>&1
[ -f "$STATE/units" ] \
  && ok "a first arm snapshots before scheduling anything" \
  || bad "armed a timer with nothing to restore"

echo
echo "== arm cancels the previous timer before scheduling a new one =="
# systemd-run refuses a --unit name that already exists, so without this the
# second arm fails and leaves the FIRST deadline standing — a timer that fires
# while you are still working, believing you had pushed it out.
fresh
harness "$UNITS_BEFORE" do_arm 10m >/dev/null 2>&1
order "systemctl stop gw-deadman.timer" "systemd-run" \
  && ok "the old timer is stopped before systemd-run is called" \
  || bad "arm schedules without cancelling the previous timer"
traced "systemctl reset-failed gw-deadman.service" \
  && ok "a failed previous run is reset, or the name stays taken" \
  || bad "a previously failed unit would block re-arming"

echo
echo "== arm hands systemd-run an absolute path =="
# The transient unit runs from /, minutes later, with no shell. A relative $0 —
# which is what `sudo scripts/deadman.sh arm` gives you — resolves to nothing at
# the one moment it matters, and the timer fires into a "no such file" that
# nobody sees.
fresh
# Deliberately a RELATIVE path, which is what `sudo scripts/deadman.sh arm`
# gives the script as $0. The test runs from the repo root, so it sources fine;
# the question is only what the script then hands to systemd-run.
DM_SCRIPT="scripts/deadman.sh" DM_UNITSTATE="$UNITS_BEFORE" DM_TRACE="$TRACE" DM_PING_RC=1 \
GW_DEADMAN_STATE="$STATE" GW_DEADMAN_LOG="$WORK/log" GW_ROOT="$ROOT" \
  bash "$WORK/harness.sh" do_arm 10m >/dev/null 2>&1
runline=$(grep '^systemd-run' "$TRACE" | head -1)
path=$(printf '%s' "$runline" | awk '{print $(NF-1)}')
case "$path" in
  /*) ok "systemd-run is given an absolute path ($path)" ;;
  *)  bad "systemd-run would run '$path', which does not resolve from /" ;;
esac
case "$runline" in
  *"--on-active=10m"*) ok "the requested delay is passed through" ;;
  *) bad "the delay did not reach systemd-run: $runline" ;;
esac
case "$runline" in
  *"--unit=gw-deadman"*) ok "the transient unit has the name disarm looks for" ;;
  *) bad "the unit name does not match what disarm stops: $runline" ;;
esac

echo
echo "== the script survives being run through a symlink =="
# Same trap as the install scripts: it sources lib/common.sh relative to
# itself. Here it matters twice, because $0 is also what gets scheduled.
LINKDIR=$(mktemp -d)
ln -sf "$DEADMAN" "$LINKDIR/dm"
out=$("$LINKDIR/dm" status 2>&1 || true)
printf '%s' "$out" | grep -q "common.sh: No such file" \
  && bad "a symlinked deadman.sh cannot find lib/common.sh" \
  || ok "it finds lib/common.sh through a symlink"
rm -rf "$LINKDIR"

echo
echo "== status and usage need no root and change nothing =="
# You reach for `status` when you are not sure whether you are still protected.
# It must answer, from any shell, without touching anything.
"$DEADMAN" status >/dev/null 2>&1 \
  && ok "status exits 0 as an ordinary user" \
  || bad "status failed without root"
"$DEADMAN" bogus >/dev/null 2>&1
[ "$?" -eq 2 ] \
  && ok "an unknown subcommand exits 2 with usage" \
  || bad "an unknown subcommand did not exit 2"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
