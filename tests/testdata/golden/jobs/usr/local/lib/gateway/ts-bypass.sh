#!/bin/sh
# Let tailscaled talk to the internet directly instead of through Xray.
#
# Two callers, two chains:
#   exceptions — permanent, when tailscale.route_control_via_xray = false
#   lifeline   — temporary, engaged by gw-health when the tunnel is stranded
#
# Matching is by systemd cgroup because tailscaled runs as root (so uid is
# useless) and talks to arbitrary DERP addresses (so daddr is useless).
#
# Two sharp edges, both handled by callers:
#   1. nft resolves the cgroup path to a cgroup ID at rule-insertion time, so
#      this cannot live in the boot-time ruleset — tailscaled isn't running yet.
#   2. That ID changes when tailscaled restarts, silently breaking the rule.
#      Hence ExecStartPost on tailscaled and the re-apply in gw-health.
set -eu

CHAIN="${1:?usage: ts-bypass.sh <exceptions|lifeline> <on|off>}"
ACTION="${2:?usage: ts-bypass.sh <exceptions|lifeline> <on|off>}"
CGROUP=/sys/fs/cgroup/system.slice/tailscaled.service

case "$ACTION" in
  on)
    [ -d "$CGROUP" ] || { echo "tailscaled cgroup not present yet" >&2; exit 1; }
    nft flush chain inet gateway "$CHAIN" 2>/dev/null || true
    nft -f - <<NFT
add rule inet gateway $CHAIN socket cgroupv2 level 2 "system.slice/tailscaled.service" accept
NFT
    ;;
  off)
    nft flush chain inet gateway "$CHAIN" 2>/dev/null || true
    ;;
  *)
    echo "usage: ts-bypass.sh <exceptions|lifeline> <on|off>" >&2; exit 2 ;;
esac
