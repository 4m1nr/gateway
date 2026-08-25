#!/usr/bin/env bash
# Tailscale: subnet router + exit node + SSH.
#
# Exit-node traffic is proxied because 100.64.0.0/10 is in @proxy_clients, so a
# remote device using this box as its exit node comes out of the Xray server.
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

if ! command -v tailscale >/dev/null; then
  info "installing Tailscale"
  curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg \
    -o /usr/share/keyrings/tailscale-archive-keyring.gpg
  curl -fsSL https://pkgs.tailscale.com/stable/debian/trixie.tailscale-keyring.list \
    -o /etc/apt/sources.list.d/tailscale.list
  apt-get update -qq
  apt-get install -y tailscale
fi

systemctl enable --now tailscaled

"$REPO/bin/gw" render >/dev/null
ARGS=$(cat "$REPO/build/tailscale-args")
[ -z "${ARGS// }" ] && die "tailscale is disabled in gateway.toml"

info "tailscale up $ARGS"
# shellcheck disable=SC2086
tailscale up $ARGS

# Applies only when route_control_via_xray = false; otherwise tailscaled's own
# traffic is captured by the OUTPUT chain along with everything else.
if [ -f /etc/systemd/system/gw-tailscale-exception.service ]; then
  info "exempting tailscaled from the tunnel (route_control_via_xray = false)"
  systemctl daemon-reload
  systemctl enable --now gw-tailscale-exception.service
fi

cat <<'NEXT'

One manual step remains, in the Tailscale admin console
(https://login.tailscale.com/admin/machines):

  * approve the advertised subnet route for your LAN
  * approve this machine as an exit node

Tailscale requires a human to approve both; nothing on the box can do it.

Next: sudo scripts/50-hardening.sh
NEXT
