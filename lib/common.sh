# Shared helpers for the install scripts. Source, don't execute.
set -euo pipefail

# nft, sysctl, ip, visudo and useradd all live in /usr/sbin, which is NOT in
# every root PATH — a plain `su`, or a root shell whose profile never added it,
# has only /usr/bin. Calling them by bare name then fails in ways that look
# like something else entirely: `gw status` reported "firewall not loaded"
# purely because it could not find nft, while `sudo gw apply` worked because
# sudo's secure_path does include /usr/sbin.
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:$PATH}"
export PATH

# Same symlink resolution as bin/gw: a script invoked through a symlink would
# otherwise compute the wrong repo root.
gw_resolve_repo() {
  local self="$1" target
  while [ -L "$self" ]; do
    target="$(readlink "$self")"
    case "$target" in
      /*) self="$target" ;;
      *)  self="$(dirname "$self")/$target" ;;
    esac
  done
  (cd "$(dirname "$self")/.." && pwd)
}

REPO="${GW_REPO:-$(gw_resolve_repo "${BASH_SOURCE[1]}")}"

c_red=$'\033[31m'; c_grn=$'\033[32m'; c_yel=$'\033[33m'; c_off=$'\033[0m'
info() { printf '%s==>%s %s\n' "$c_grn" "$c_off" "$*"; }
warn() { printf '%s[!]%s %s\n' "$c_yel" "$c_off" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$c_red" "$c_off" "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "this script needs root"; }

confirm() {
  local prompt="$1"
  [ "${GW_YES:-0}" = "1" ] && return 0
  read -r -p "$prompt [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || die "aborted"
}

# ---------------------------------------------------------------- proxy ----
# Setup runs before the tunnel exists, so these jobs may need a way out that
# the gateway itself cannot yet provide. GW_PROXY (env, or `gw --proxy`)
# overrides bootstrap.socks_proxy from the config.
#
# None of this applies once the gateway is running: the box's own traffic is
# routed through Xray by the OUTPUT chain.
gw_proxy() {
  if [ -n "${GW_PROXY:-}" ]; then printf '%s' "$GW_PROXY"; return; fi
  sed -n 's/^socks_proxy *= *"\(.*\)"/\1/p' \
    <(sed -n '/^\[bootstrap\]/,/^\[/p' "$CONFIG") | head -1
}

gw_curl() {
  local proxy; proxy=$(gw_proxy)
  if [ -n "$proxy" ]; then curl -fsSL --proxy "$proxy" "$@"; else curl -fsSL "$@"; fi
}

# See templates/lib/net.sh for why this is not just `runuser`.
gw_as_user() {
  local user="$1"; shift
  local uid gid
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

APT_PROXY_CONF=/etc/apt/apt.conf.d/99-gw-bootstrap-proxy
apt_proxy_on() {
  local proxy; proxy=$(gw_proxy)
  [ -z "$proxy" ] && return 0
  info "routing apt through the bootstrap proxy: $proxy"
  cat > "$APT_PROXY_CONF" <<CONF
// Written by the gateway setup scripts for this run only.
Acquire::http::Proxy "$proxy";
Acquire::https::Proxy "$proxy";
CONF
  # Removed even if the script dies, so apt is never left pointing at a proxy
  # that has gone away.
  trap 'rm -f "$APT_PROXY_CONF"' EXIT
}
apt_proxy_off() { rm -f "$APT_PROXY_CONF"; }

# version_of <component> — read a pin out of versions.toml without a TOML parser
version_of() {
  sed -n "/^\[$1\]/,/^\[/p" "$REPO/versions.toml" \
    | sed -n 's/^version *= *"\(.*\)"/\1/p' | head -1
}
sha_of() {
  sed -n "/^\[$1\]/,/^\[/p" "$REPO/versions.toml" \
    | sed -n 's/^sha256 *= *"\(.*\)"/\1/p' | head -1
}

# verify_sha <file> <expected-or-empty> <fallback-digest-url>
verify_sha() {
  local file="$1" expected="$2" dgst_url="${3:-}" actual
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ -n "$expected" ]; then
    [ "$actual" = "$expected" ] || die "checksum mismatch for $file
  expected $expected
  got      $actual"
    info "checksum verified against the pin in versions.toml"
    return 0
  fi
  if [ -n "$dgst_url" ] && gw_curl --max-time 30 "$dgst_url" -o "$file.dgst" 2>/dev/null; then
    if grep -qi "$actual" "$file.dgst"; then
      info "checksum matches the published digest"
      warn "that digest came from the same host as the download — it proves the file is intact, not that it is authentic. Pin sha256 in versions.toml to fix that."
      return 0
    fi
    die "published digest does not match $file"
  fi
  warn "no checksum available for $file — proceeding unverified"
}

# The repo may be checked out anywhere; the config lives beside it.
CONFIG="${GW_CONFIG:-$REPO/gateway.toml}"
[ -f "$CONFIG" ] || die "$CONFIG not found — run \`gw init\` first"
