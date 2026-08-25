# Shared helpers for the install scripts. Source, don't execute.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[1]}")/.." && pwd)"

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
  if [ -n "$dgst_url" ] && curl -fsSL --max-time 30 "$dgst_url" -o "$file.dgst" 2>/dev/null; then
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
