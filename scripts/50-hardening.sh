#!/usr/bin/env bash
# Lock down the box now that it is the path to the internet for other devices.
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
require_config

info "hardening sshd"
install -d /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/99-gateway.conf <<'CONF'
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
CONF

if [ ! -s /root/.ssh/authorized_keys ] && \
   [ -z "$(find /home -maxdepth 3 -name authorized_keys -size +0 2>/dev/null)" ]; then
  warn "no authorized_keys found anywhere — leaving password auth ON so you"
  warn "don't lock yourself out. Add a key, then re-run this script."
  rm -f /etc/ssh/sshd_config.d/99-gateway.conf
else
  sshd -t && systemctl reload ssh
  info "password authentication disabled"
fi

if grep -q '^unattended_upgrades *= *true' "$CONFIG"; then
  info "enabling unattended security upgrades"
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
CONF
  # Never reboot on its own: an unattended reboot takes the LAN's internet with
  # it, and the tunnel needs a health check afterwards anyway.
  sed -i 's|^//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "false";|' \
    /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null || true
fi

info "enabling the gateway stack for boot"
"$REPO/bin/gw" enable

info "done — run 'sudo gw check' to verify the whole path"
