#!/usr/bin/env bash
# Web dashboard: unprivileged service user, self-signed cert, sudoers gate.
#
# The dashboard can rewrite the firewall, so it is fenced three ways:
#   1. nftables only accepts its port from web.allow_cidrs
#   2. the app re-checks the peer address against the same list
#   3. a scrypt-hashed password, verified across the sudo boundary
source "$(dirname "$0")/../lib/common.sh"
need_root

grep -q '^enabled = true' <(sed -n '/^\[web\]/,/^\[/p' "$CONFIG") \
  || die "web.enabled is false in $CONFIG — nothing to install"

if ! id gwweb >/dev/null 2>&1; then
  info "creating the gwweb service user"
  # No home, no shell, no group memberships: it exists to own one process.
  useradd --system --no-create-home --shell /usr/sbin/nologin gwweb
fi

"$REPO/bin/gw" render >/dev/null
PORT=$(sed -n 's/.*"port": *\([0-9]*\).*/\1/p' "$REPO/build/etc/gateway/web.json")
TLS=$(grep -q '"tls": *true' "$REPO/build/etc/gateway/web.json" && echo yes || echo no)
BOX=$(sed -n 's/^BOX_IP=//p' "$REPO/build/usr/local/lib/gateway/env")

install -d -m 0755 /etc/gateway

if [ "$TLS" = yes ] && [ ! -f /etc/gateway/web.key ]; then
  info "generating a self-signed certificate for $BOX"
  command -v openssl >/dev/null || apt-get install -y --no-install-recommends openssl
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /etc/gateway/web.key -out /etc/gateway/web.crt \
    -subj "/CN=gateway.local" \
    -addext "subjectAltName=IP:$BOX,DNS:gateway.local" >/dev/null 2>&1
  chmod 0640 /etc/gateway/web.key
  chgrp gwweb /etc/gateway/web.key
  chmod 0644 /etc/gateway/web.crt
  warn "self-signed: your browser warns once. It stops the password crossing"
  warn "the LAN in clear text, but a LAN attacker could still substitute their"
  warn "own certificate and you would click through. Use Tailscale if that matters."
fi

info "installing the dashboard"
"$REPO/bin/gw" apply

if [ ! -f /etc/gateway/web-auth.json ]; then
  echo
  warn "No dashboard password is set — the login page will refuse every attempt."
  echo "Set one now:"
  echo
  "$REPO/bin/gw" web-passwd || warn "skipped; run 'sudo gw web-passwd' before using the dashboard"
fi

SCHEME=http; [ "$TLS" = yes ] && SCHEME=https
cat <<NEXT

Dashboard: $SCHEME://$BOX:$PORT

Reachable only from: $(sed -n 's/.*"allow_cidrs".*//p' /etc/gateway/web.json >/dev/null; python3 -c "
import json;print(', '.join(json.load(open('/etc/gateway/web.json'))['allow_cidrs']))")

Next: sudo scripts/50-hardening.sh
NEXT
