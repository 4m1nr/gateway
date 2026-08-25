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
  if [ -n "$proxy" ]; then
    curl -fsSL --proxy "$proxy" "$@"
  else
    curl -fsSL "$@"
  fi
}
