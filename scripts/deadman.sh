#!/usr/bin/env bash
# Dead-man switch for installing over SSH.
#
# `gw panic` is the in-band escape hatch: you run it when you can still get a
# shell. This is the out-of-band one, for when you cannot — it rolls the box
# back on a timer that only your continued presence cancels.
#
#   sudo scripts/deadman.sh arm 10m    # snapshot now, restore in 10 minutes
#   ...run an install step...
#   sudo scripts/deadman.sh arm 10m    # still here? push the deadline out
#   sudo scripts/deadman.sh disarm     # done, and not locked out
#
# `gw panic` is not enough on its own here. It removes the nft table and the
# policy routing, but 00-bootstrap.sh also replaces the box's whole network
# configuration — NetworkManager off, systemd-networkd on, a static address
# from gateway.toml — and gw-network.service is WantedBy=sysinit.target. Get
# any of that wrong and the box is unreachable *and* comes back unreachable
# after a reboot. So restore undoes the persistent state too.
_self="$0"
while [ -L "$_self" ]; do
  _link="$(readlink "$_self")"
  case "$_link" in /*) _self="$_link" ;; *) _self="$(dirname "$_self")/$_link" ;; esac
done
# Absolute, because `arm` hands this path to systemd-run and the transient unit
# runs from / — a relative path captured from `scripts/deadman.sh` would resolve
# to nothing when the timer finally fires, which is the one moment it matters.
_self="$(cd "$(dirname "$_self")" && pwd)/$(basename "$_self")"
source "$(dirname "$_self")/../lib/common.sh"

# /var/lib, not /run: a snapshot that vanishes on reboot is worthless to the
# case this exists for, where the box reboots into the broken configuration.
# Overridable so the snapshot/restore pair can be exercised against a throwaway
# directory.
STATE="${GW_DEADMAN_STATE:-/var/lib/gateway/deadman}"
LOG="${GW_DEADMAN_LOG:-/var/log/gw-deadman.log}"
UNIT=gw-deadman

# Prefix for the system files restore rewrites, so the tests can point the whole
# lot at a scratch tree and check that the files really are gone or really are
# back — rather than that the right `rm` was spelled. Same seam as apply's
# --root and ip-rules.sh's GW_NET_CONF. Empty in every real run.
ROOT="${GW_ROOT:-}"
RESOLV="$ROOT/etc/resolv.conf"
WAN_NETWORK="$ROOT/etc/systemd/network/10-gateway-wan.network"
GW_SYSCTL="$ROOT/etc/sysctl.d/99-gateway.conf"
IP_RULES="$ROOT/usr/local/lib/gateway/ip-rules.sh"

# Units whose enabled/active state the install changes and restore must put
# back. nftables.service is here because bootstrap masks it.
TRACKED=(
  NetworkManager.service
  networking.service
  systemd-networkd.service
  systemd-networkd-wait-online.service
  systemd-resolved.service
  wpa_supplicant.service
  nftables.service
)

# Everything the gateway installs that can hold the network down. Stopped and
# disabled on restore — disabled matters, because gw-network.service loads the
# ruleset from sysinit.target on every boot.
GW_UNITS=(
  gateway.target
  gw-network.service
  xray.service
  gw-health.timer
  gw-geoupdate.timer
  gw-update.timer
  gw-web.service
  gw-tailscale-exception.service
)

log() { printf '%s %s\n' "$(date -Is)" "$*" >> "$LOG"; }

# ------------------------------------------------------------------ snapshot --
# Record what "working" looks like, before anything touches it.
do_snapshot() {
  need_root
  install -d -m 0700 "$STATE"

  # resolv.conf may be a symlink into /run (systemd-resolved) or a real file.
  # Which one it is has to be recorded, or restore turns a managed symlink into
  # a stale copy and name resolution breaks in a way that outlives the rollback.
  if [ -L "$RESOLV" ]; then
    printf 'symlink %s\n' "$(readlink "$RESOLV")" > "$STATE/resolv.kind"
  elif [ -f "$RESOLV" ]; then
    printf 'file\n' > "$STATE/resolv.kind"
    cp -a "$RESOLV" "$STATE/resolv.conf"
  else
    printf 'absent\n' > "$STATE/resolv.kind"
  fi

  # `systemctl is-enabled` on a unit that does not exist prints "not-found" AND
  # exits non-zero, so a bare `|| echo unknown` appends a SECOND line and the
  # record becomes three lines pretending to be one. head -1 first, then fall
  # back only on genuinely empty output.
  : > "$STATE/units"
  local u en ac
  for u in "${TRACKED[@]}"; do
    # `|| true` is load-bearing twice over: is-enabled exits 4 for a unit that
    # does not exist — networking.service on a networkd box, wpa_supplicant on
    # a wired one — and common.sh sets `set -euo pipefail`, so without it the
    # snapshot aborts partway through and arms a timer with half a record.
    en=$(systemctl is-enabled "$u" 2>/dev/null | head -1) || true
    ac=$(systemctl is-active  "$u" 2>/dev/null | head -1) || true
    [ -n "$en" ] || en=unknown
    [ -n "$ac" ] || ac=unknown
    printf '%s %s %s\n' "$u" "$en" "$ac" >> "$STATE/units"
  done

  # Reference dumps. Not replayed automatically — restoring routes blindly is
  # how you end up with a half-state nobody can reason about — but they are the
  # first thing you want when reading the log afterwards.
  ip -br addr        > "$STATE/addr"   2>&1 || true
  ip route show      > "$STATE/route"  2>&1 || true
  ip rule show       > "$STATE/rule"   2>&1 || true
  nft list ruleset   > "$STATE/nft"    2>&1 || true

  # The WAN interface, so restore can flush the static address off it. Read
  # from the config the same way bootstrap does; it may not exist yet.
  if [ -f "$CONFIG" ]; then
    sed -n 's/^wan_if *= *"\(.*\)"/\1/p' "$CONFIG" | head -1 > "$STATE/wan_if"
    sed -n 's/^router *= *"\(.*\)"/\1/p' "$CONFIG" | head -1 > "$STATE/router"
  fi

  # Who to prove reachability to afterwards. sudo strips SSH_CONNECTION under
  # the default env_reset, so fall back to the live sshd sessions.
  { [ -n "${SSH_CONNECTION:-}" ] && awk '{print $1}' <<< "$SSH_CONNECTION"
    who --ips 2>/dev/null | awk '{print $NF}' | tr -d '()'
  } 2>/dev/null | grep -E '^[0-9.]+$' | sort -u > "$STATE/peers" || true

  log "snapshot taken"
  info "snapshot in $STATE"
}

# ------------------------------------------------------------------- restore --
# Runs unattended, from a timer, on a box that may have no network. So: no
# prompts, no network access, nothing that can hang, and `|| true` on
# everything — a failure in step 3 must not skip steps 4 through 8.
do_restore() {
  need_root
  log "=== restore starting ==="
  warn "rolling the gateway back"

  # No snapshot means someone ran `restore` by hand without arming. Tearing the
  # gateway down is still the right thing; only the "put it back as it was"
  # half has nothing to work from.
  if [ ! -f "$STATE/units" ]; then
    warn "no snapshot in $STATE — tearing the gateway down, restoring nothing"
    log "no snapshot; teardown only"
    install -d -m 0700 "$STATE"
    : > "$STATE/units"
  fi

  # 1. The gateway stack. Disable as well as stop: several of these are pulled
  #    in at boot, so stopping alone lasts until the next reboot.
  local u
  for u in "${GW_UNITS[@]}"; do
    systemctl stop "$u" >/dev/null 2>&1 || true
    systemctl disable "$u" >/dev/null 2>&1 || true
  done
  log "gateway units stopped and disabled"

  # 2. The ruleset and the policy routing. The table goes first, so nothing is
  #    still being intercepted while the routing that serves it is torn down.
  nft delete table inet gateway >/dev/null 2>&1 || true
  nft delete table ip gwpanic   >/dev/null 2>&1 || true
  if [ -x "$IP_RULES" ]; then
    "$IP_RULES" down >/dev/null 2>&1 || true
  fi
  # By hand as well: ip-rules.sh needs its env file, and if that was never
  # installed the rules are still there and still divert everything to lo.
  ip rule del fwmark 1 lookup 100 >/dev/null 2>&1 || true
  ip route flush table 100        >/dev/null 2>&1 || true
  log "nft tables and policy routing removed"

  # 3. The generated network and kernel configuration.
  rm -f "$WAN_NETWORK"
  rm -f "$GW_SYSCTL"
  sysctl --system >/dev/null 2>&1 || true
  log "generated network and sysctl files removed"

  # 4. Hand the interface back. systemd-networkd has to let go of the static
  #    address before another manager can configure the link, and it will not
  #    do that just because it was stopped.
  local wan prev_networkd
  wan=$(cat "$STATE/wan_if" 2>/dev/null || true)
  prev_networkd=$(awk '$1=="systemd-networkd.service"{print $2}' "$STATE/units" 2>/dev/null || true)
  if [ "$prev_networkd" != "enabled" ]; then
    systemctl stop systemd-networkd.socket systemd-networkd.service >/dev/null 2>&1 || true
    if [ -n "$wan" ]; then
      ip addr flush dev "$wan" >/dev/null 2>&1 || true
      log "flushed $wan"
    fi
  fi

  # 5. Put the tracked units back exactly as they were. Enable/disable first
  #    across the board, then start — starting NetworkManager while networkd
  #    is still up gives two managers one interface.
  local unit want_enabled want_active
  while read -r unit want_enabled want_active; do
    [ -n "$unit" ] || continue
    case "$want_enabled" in
      enabled|enabled-runtime)
        systemctl unmask "$unit" >/dev/null 2>&1 || true
        systemctl enable "$unit" >/dev/null 2>&1 || true ;;
      disabled)
        # unmask as well: bootstrap MASKS nftables.service, and a snapshot
        # taken beforehand records it merely disabled. Disabling a masked unit
        # succeeds and leaves it masked, so without this the box comes out of
        # a rollback unable to start it at all.
        systemctl unmask  "$unit" >/dev/null 2>&1 || true
        systemctl disable "$unit" >/dev/null 2>&1 || true ;;
      masked|masked-runtime)
        systemctl mask "$unit" >/dev/null 2>&1 || true ;;
      *) : ;;   # static, generated, unknown, not-found: leave alone
    esac
  done < "$STATE/units"

  while read -r unit want_enabled want_active; do
    [ -n "$unit" ] || continue
    [ "$want_enabled" = "not-found" ] && continue
    if [ "$want_active" = "active" ]; then
      systemctl start "$unit" >/dev/null 2>&1 || true
    elif [ "$want_active" = "inactive" ]; then
      systemctl stop "$unit" >/dev/null 2>&1 || true
    fi
  done < "$STATE/units"
  log "tracked units restored"

  # 6. Resolution. Routing alone is not "working network": the box may still be
  #    pointed at an AdGuard that is no longer running.
  case "$(cat "$STATE/resolv.kind" 2>/dev/null || echo missing)" in
    symlink)
      ln -sfn "$(sed 's/^symlink //' "$STATE/resolv.kind")" "$RESOLV" ;;
    file)
      cp -a "$STATE/resolv.conf" "$RESOLV" ;;
    *)
      warn "no resolv.conf snapshot — leaving it alone" ;;
  esac
  log "resolv.conf restored"

  # 7. Did it work? Only reported, never acted on beyond the reboot below: a
  #    script that keeps trying things on an unreachable box just makes the
  #    state harder to read when someone finally walks over to it.
  local router ok=0 tried=0 target
  router=$(cat "$STATE/router" 2>/dev/null || true)
  sleep 5
  # The SSH peer first: it is the only address that answers the question this
  # whole script exists for, which is whether the person who armed it can get
  # back in. The router is the fallback for a console-armed run.
  for target in $(cat "$STATE/peers" 2>/dev/null || true) $router; do
    tried=$((tried + 1))
    if ping -c2 -W3 "$target" >/dev/null 2>&1; then
      log "$target reachable"
      ok=1
    else
      log "$target NOT reachable after restore"
    fi
  done
  [ "$ok" -eq 1 ] || log "nothing reachable after restore"
  ip -br addr >> "$LOG" 2>&1 || true

  # 8. Last resort, opt-in. Everything above has already disabled the units
  #    that would otherwise reassert themselves, so a reboot now comes up in
  #    the pre-install configuration rather than back into the broken one.
  # tried > 0 as well: with no peer and no router recorded there is nothing to
  # probe, and "I could not check" must not be treated as "it is broken".
  if [ "$ok" -eq 0 ] && [ "$tried" -gt 0 ] && [ "${GW_DEADMAN_REBOOT:-0}" = "1" ]; then
    log "still unreachable and GW_DEADMAN_REBOOT=1 — rebooting"
    systemctl reboot
  fi

  log "=== restore finished ==="
  info "rollback complete — see $LOG"
}

# ---------------------------------------------------------------------- arm --
do_arm() {
  need_root
  local when="${1:-10m}"

  # Re-arming is the normal case: you run this between install steps to push
  # the deadline out. Cancel the old timer rather than failing on the name.
  systemctl stop "$UNIT.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$UNIT.service" >/dev/null 2>&1 || true

  # Snapshot only once. The whole point is to capture the state from BEFORE
  # the install; re-snapshotting on every re-arm would faithfully record the
  # broken configuration and restore it.
  if [ -f "$STATE/units" ]; then
    info "keeping the existing snapshot from $(stat -c %y "$STATE/units" | cut -d. -f1)"
  else
    do_snapshot
  fi

  systemd-run --unit="$UNIT" --on-active="$when" --timer-property=AccuracySec=1s \
    --description="Gateway dead-man rollback" \
    "$_self" restore >/dev/null

  info "armed: restoring in $when unless disarmed"
  warn "disarm with: sudo $0 disarm"
  do_status
}

do_disarm() {
  need_root
  systemctl stop "$UNIT.timer" >/dev/null 2>&1 || true
  systemctl reset-failed "$UNIT.service" >/dev/null 2>&1 || true
  if systemctl list-timers --all 2>/dev/null | grep -q "$UNIT"; then
    die "timer still present — check: systemctl list-timers $UNIT.timer"
  fi
  info "disarmed. The snapshot is kept; drop it with: $0 forget"
}

do_status() {
  if systemctl is-active "$UNIT.timer" >/dev/null 2>&1; then
    systemctl list-timers --all "$UNIT.timer" --no-pager | sed -n '1,2p'
  else
    info "not armed"
  fi
  [ -f "$STATE/units" ] \
    && info "snapshot: $STATE (taken $(stat -c %y "$STATE/units" | cut -d. -f1))" \
    || info "no snapshot"
}

do_forget() { need_root; rm -rf "$STATE"; info "snapshot dropped"; }

case "${1:-status}" in
  arm)      shift; do_arm "$@" ;;
  disarm)   do_disarm ;;
  status)   do_status ;;
  snapshot) do_snapshot ;;
  restore)  do_restore ;;
  forget)   do_forget ;;
  *) cat >&2 <<USAGE
usage: $0 {arm [duration] | disarm | status | snapshot | restore | forget}

  arm [10m]   snapshot the current network state, then restore it after the
              given delay unless disarmed. Re-arming resets the clock and
              keeps the original snapshot.
  disarm      cancel the timer (the snapshot is kept)
  status      is it armed, and how long is left
  snapshot    record the current state without arming
  restore     roll back now — this is what the timer runs
  forget      drop the snapshot

  GW_DEADMAN_REBOOT=1  reboot if the router is still unreachable after a
                       restore. Safe by then: restore has already disabled the
                       units that would otherwise come back at boot.
USAGE
     exit 2 ;;
esac
