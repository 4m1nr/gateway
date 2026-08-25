# nft, sysctl, ip, visudo and useradd all live in /usr/sbin, which is NOT in
# every root PATH — a plain `su`, or a root shell whose profile never added it,
# has only /usr/bin. Calling them by bare name then fails in ways that look
# like something else entirely: `gw status` reported "firewall not loaded"
# purely because it could not find nft, while `sudo gw apply` worked because
# sudo's secure_path does include /usr/sbin.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

# Shared network helpers. Source, don't execute.
#
# Everything that fetches something during setup or update goes through
# gw_curl, so a single bootstrap proxy setting covers all of it.
#
# This matters only before the tunnel exists. Once the gateway is running, the
# box's own traffic is already routed through Xray by the OUTPUT chain, and
# BOOTSTRAP_PROXY should normally be left empty.

# GW_PROXY (environment) overrides the configured value, for one-off runs.
gw_proxy() {
  if [ -n "${GW_PROXY:-}" ]; then
    printf '%s' "$GW_PROXY"
  else
    printf '%s' "${BOOTSTRAP_PROXY:-}"
  fi
}

gw_curl() {
  proxy=$(gw_proxy)
  # Timeouts first so a caller's own --max-time overrides them (curl takes the
  # last occurrence). Without a cap an unreachable host hangs setup for minutes
  # with no output — which is the normal failure mode on the networks this box
  # exists to work around, not an edge case.
  set -- --connect-timeout 15 --max-time 120 "$@"
  if [ -n "$proxy" ]; then
    curl -fsSL --proxy "$proxy" "$@"
  else
    curl -fsSL "$@"
  fi
}

# Run a command as another user, for the direct-egress test.
#
# The xray uid is exempt from the OUTPUT chain, so anything running as it
# bypasses the tunnel — which is how we see the box's real address.
#
# setpriv first: runuser moved from util-linux to util-linux-extra in Debian
# 12, so it is simply absent on a minimal install, which is what a thin client
# gets. `bash: runuser: command not found` is not a useful diagnostic.
gw_as_user() {
  user="$1"; shift
  # Numeric ids: some setpriv builds reject a group NAME for --regid, and the
  # failure ("failed to parse regid") is far from obvious.
  uid=$(id -u "$user" 2>/dev/null) || { echo "no such user: $user" >&2; return 1; }
  gid=$(id -g "$user" 2>/dev/null) || gid="$uid"

  # Probe each method before committing to it. setpriv is preferred because
  # runuser moved to util-linux-extra in Debian 12 and is absent from a minimal
  # install — but setpriv's --clear-groups needs privileges that some
  # environments withhold, so a failure here should fall through rather than
  # take the caller down with it.
  if command -v setpriv >/dev/null 2>&1 &&
     setpriv --reuid="$uid" --regid="$gid" --clear-groups true 2>/dev/null; then
    setpriv --reuid="$uid" --regid="$gid" --clear-groups "$@"
  elif command -v runuser >/dev/null 2>&1 && runuser -u "$user" -- true 2>/dev/null; then
    runuser -u "$user" -- "$@"
  elif command -v sudo >/dev/null 2>&1 && sudo -n -u "$user" -- true 2>/dev/null; then
    sudo -n -u "$user" -- "$@"
  else
    echo "cannot run as $user: no working setpriv, runuser or sudo" >&2
    return 127
  fi
}
