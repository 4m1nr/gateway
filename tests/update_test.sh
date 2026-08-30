#!/usr/bin/env bash
# The update path: download, verify, test, install, roll back.
#
# This is the code with the worst failure mode in the repo. It runs unattended,
# as root, on the box the whole house routes through, and every guarantee it
# makes is about NOT leaving the gateway broken: a bad checksum must abort, a
# binary the live config would reject must abort, and a service that will not
# come back must be rolled back to the one that did.
#
# None of that was covered. These tests run the real scripts against a scratch
# tree, with fakes for the three things that reach outside it — the network, the
# release archive, and systemd.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

for tool in unzip zip sha256sum; do
  command -v "$tool" >/dev/null || { echo "  - $tool is missing; skipping"; exit 0; }
done

ROOT=$(mktemp -d); trap 'rm -rf "$ROOT"' EXIT

# ---------------------------------------------------------------- fixtures --

# A fake Xray: answers `version`, and accepts or rejects a config depending on
# how it was built. That second behaviour is what the "tests the new binary
# against the live config" guarantee is made of.
make_xray() {
  local path="$1" version="$2" accepts="$3"
  cat > "$path" <<FAKE
#!/bin/bash
case "\$1" in
  version) echo "Xray $version (Xray, Penetrates Everything.)"; exit 0 ;;
  run)
    for a in "\$@"; do [ "\$a" = "-test" ] && { [ "$accepts" = yes ] && exit 0 || {
      echo "config rejected by $version" >&2; exit 1; }; }; done
    exit 0 ;;
esac
exit 0
FAKE
  chmod +x "$path"
}

# A release archive containing that binary, plus the geodata a real one ships.
make_release() {
  local zip="$1" version="$2" accepts="$3"
  local stage; stage=$(mktemp -d)
  make_xray "$stage/xray" "$version" "$accepts"
  head -c 1000 /dev/zero | tr '\0' 'g' > "$stage/geoip.dat"
  head -c 1000 /dev/zero | tr '\0' 'g' > "$stage/geosite.dat"
  ( cd "$stage" && zip -q "$zip" xray geoip.dat geosite.dat )
  rm -rf "$stage"
}

# A world for one test: the paths the script writes to, a fake systemd whose
# behaviour the test dictates, and a curl that serves the local archive.
setup() {
  local name="$1" archive="$2" restart_behaviour="$3"
  W="$ROOT/$name"; rm -rf "$W"
  mkdir -p "$W"/{bin,lib/gateway,usr/local/bin,usr/local/share/xray,usr/local/etc/xray,repo}

  printf 'BOOTSTRAP_PROXY=""\n' > "$W/lib/gateway/env"

  # A stand-in for net.sh that serves the local archive.
  #
  # Not a PATH shim: net.sh deliberately PREPENDS the system directories so
  # sbin tools are always found, which means a fake curl earlier on PATH would
  # be ignored — the very behaviour that fixed `gw status` reporting "firewall
  # not loaded". So the network layer is replaced wholesale, and gw_proxy's own
  # behaviour is covered by tests/proxy_test.sh instead.
  cat > "$W/lib/gateway/net.sh" <<NET
gw_proxy() { printf ''; }
gw_curl() { "$W/bin/curl" "\$@"; }
gw_as_user() { shift; "\$@"; }
NET
  printf '{"inbounds":[],"outbounds":[]}\n' > "$W/usr/local/etc/xray/config.json"
  printf '[xray]\nversion = "v1.0.0"\n' > "$W/repo/versions.toml"

  # curl: every URL is served from the local archive, except the .dgst probe
  # which 404s unless a test provides one.
  cat > "$W/bin/curl" <<CURL
#!/bin/bash
out=""; url=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    -w) shift 2 ;;
    http*|https*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
case "\$url" in
  *.dgst) [ -f "$W/dgst" ] && { cp "$W/dgst" "\$out"; exit 0; }; exit 22 ;;
  */releases/latest) printf '%s' "https://example/tag/\$(cat "$W/latest" 2>/dev/null || echo v2.0.0)"; exit 0 ;;
  *.zip) cp "$archive" "\$out"; exit 0 ;;
esac
exit 22
CURL
  chmod +x "$W/bin/curl"

  # systemd: active or not, and a restart that succeeds, fails, or "succeeds"
  # and then dies — the three outcomes the rollback logic distinguishes.
  cat > "$W/bin/systemctl" <<SYSTEMD
#!/bin/bash
behaviour="$restart_behaviour"
case "\$1 \$2" in
  "is-active --quiet")
    case "\$behaviour" in
      inactive) exit 3 ;;
      dies-after-restart) [ -f "$W/restarted" ] && exit 3 || exit 0 ;;
      *) exit 0 ;;
    esac ;;
esac
case "\$1" in
  restart|start)
    touch "$W/restarted"
    echo "\$1 \$2" >> "$W/systemctl.log"
    [ "\$behaviour" = "restart-fails" ] && exit 1
    exit 0 ;;
esac
exit 0
SYSTEMD
  chmod +x "$W/bin/systemctl"
}

# run <archive-version-args...> — invokes the real script in that world.
run_update() {
  ( export PATH="$W/bin:$PATH" \
           GW_LIB="$W/lib/gateway" \
           GW_XRAY_BIN="$W/usr/local/bin/xray" \
           GW_XRAY_SHARE="$W/usr/local/share/xray" \
           GW_XRAY_CONFIG="$W/usr/local/etc/xray/config.json" \
           REPO="$W/repo"
    bash templates/lib/xray-update.sh "$@" ) >"$W/out" 2>&1
}

installed_version() {
  [ -x "$W/usr/local/bin/xray" ] && "$W/usr/local/bin/xray" version | head -1 || echo "none"
}

GOOD="$ROOT/good.zip"; make_release "$GOOD" "v2.0.0" yes
BAD="$ROOT/rejects.zip"; make_release "$BAD" "v2.0.0" no

# -------------------------------------------------------------------- tests --

echo "== a binary the live config rejects is never installed =="
# The guarantee that matters most: found out here, not when the service fails
# to come back with no easy way in.
setup reject "$BAD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
run_update v2.0.0
if grep -q 'rejects the current config' "$W/out" && installed_version | grep -q 'v1.0.0'; then
  ok "aborts, and the working binary is untouched"
else
  bad "a config-rejecting binary was installed: $(installed_version)"
  sed 's/^/      /' "$W/out" | tail -4
fi
[ -e "$W/usr/local/bin/xray.previous" ] \
  && bad "it kept a .previous even though nothing was replaced" \
  || ok "no stale .previous is left behind"

echo
echo "== a checksum that does not match the pin aborts =="
setup badsum "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
printf '[xray]\nversion = "v2.0.0"\nsha256 = "%s"\n' \
  "0000000000000000000000000000000000000000000000000000000000000000" > "$W/repo/versions.toml"
run_update v2.0.0
if grep -q 'checksum mismatch' "$W/out" && installed_version | grep -q 'v1.0.0'; then
  ok "aborts on a mismatched pin, binary untouched"
else
  bad "a mismatched checksum was accepted"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== a matching pin is accepted =="
setup goodsum "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
printf '[xray]\nversion = "v2.0.0"\nsha256 = "%s"\n' \
  "$(sha256sum "$GOOD" | cut -d' ' -f1)" > "$W/repo/versions.toml"
run_update v2.0.0
if grep -q 'checksum verified' "$W/out" && installed_version | grep -q 'v2.0.0'; then
  ok "installs when the pin matches"
else
  bad "a correct checksum was rejected"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== a published digest that disagrees aborts =="
setup baddgst "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
printf 'deadbeef  Xray-linux-64.zip\n' > "$W/dgst"
run_update v2.0.0
if grep -q 'published digest does not match' "$W/out" && installed_version | grep -q 'v1.0.0'; then
  ok "aborts when the published digest disagrees"
else
  bad "a bad published digest was accepted"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== the previous binary is kept, and restored when the service will not start =="
setup rollback "$GOOD" restart-fails
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
run_update v2.0.0
if grep -q 'rolling back' "$W/out"; then
  ok "reports the rollback"
else
  bad "a failed restart did not roll back"; sed 's/^/      /' "$W/out" | tail -4
fi
if installed_version | grep -q 'v1.0.0'; then
  ok "the working binary is back in place"
else
  bad "after rollback the installed binary is $(installed_version), not v1.0.0"
fi
if grep -c 'restart xray' "$W/systemctl.log" 2>/dev/null | grep -qv '^1$'; then
  ok "the service was restarted again on the old binary"
else
  bad "the service was left down after rolling back"
fi

echo
echo "== and when it starts but does not stay up =="
# A restart that exits 0 and then dies is the harder case, and the one a naive
# check misses entirely.
setup flapping "$GOOD" dies-after-restart
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
run_update v2.0.0
if grep -q 'did not stay up' "$W/out" && installed_version | grep -q 'v1.0.0'; then
  ok "rolls back a binary that starts and then dies"
else
  bad "a flapping service was left on the new binary: $(installed_version)"
  sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== a clean update installs and keeps the previous binary =="
setup happy "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
run_update v2.0.0
if installed_version | grep -q 'v2.0.0'; then
  ok "the new version is installed"
else
  bad "the update did not install: $(installed_version)"; sed 's/^/      /' "$W/out" | tail -4
fi
if [ -x "$W/usr/local/bin/xray.previous" ] \
   && "$W/usr/local/bin/xray.previous" version | grep -q 'v1.0.0'; then
  ok "the previous binary is kept for a rollback"
else
  bad "no usable .previous was kept, so a later failure could not roll back"
fi

echo
echo "== geodata is seeded only when absent =="
# The updater ships geoip/geosite, but `gw agent geoupdate` owns them after the
# first install. Overwriting would silently undo a geodata update.
setup geo "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
printf 'CURRENT-DATA' > "$W/usr/local/share/xray/geoip.dat"
run_update v2.0.0
if [ "$(cat "$W/usr/local/share/xray/geoip.dat")" = "CURRENT-DATA" ]; then
  ok "existing geodata is left alone"
else
  bad "the updater overwrote geodata that geoupdate owns"
fi
[ -s "$W/usr/local/share/xray/geosite.dat" ] \
  && ok "missing geodata is seeded from the release" \
  || bad "geosite.dat was not seeded when absent"

echo
echo "== --check changes nothing =="
setup check "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v1.0.0" yes
before=$(sha256sum "$W/usr/local/bin/xray" | cut -d' ' -f1)
run_update --check
after=$(sha256sum "$W/usr/local/bin/xray" | cut -d' ' -f1)
if [ "$before" = "$after" ] && grep -q 'installed' "$W/out"; then
  ok "reports without touching the binary"
else
  bad "--check modified something"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== re-running on the installed version is a no-op =="
setup noop "$GOOD" ok
make_xray "$W/usr/local/bin/xray" "v2.0.0" yes
run_update v2.0.0
if grep -q 'already installed' "$W/out" && [ ! -e "$W/restarted" ]; then
  ok "does not restart the service for nothing"
else
  bad "re-running restarted the service"; sed 's/^/      /' "$W/out" | tail -4
fi

# ============================================================== AdGuard Home ==
#
# The same sequence, and the same failure to avoid: AdGuard serves DNS for the
# whole LAN, so a version that will not start takes every device offline even
# though the tunnel is fine — and DNS failing looks nothing like a DNS problem
# from a client.

# A fake AdGuardHome. --check-config accepts or rejects, which is the
# pre-flight the script relies on.
make_adguard() {
  local path="$1" version="$2" accepts="$3"
  cat > "$path" <<FAKE
#!/bin/bash
case "\$1" in
  --version) echo "AdGuard Home, version $version"; exit 0 ;;
  --help) echo "  --check-config  check the configuration"; exit 0 ;;
  --check-config) [ "$accepts" = yes ] && exit 0 || { echo "rejected" >&2; exit 1; } ;;
esac
exit 0
FAKE
  chmod +x "$path"
}

make_adguard_release() {
  local tgz="$1" version="$2" accepts="$3"
  local stage; stage=$(mktemp -d)
  mkdir -p "$stage/AdGuardHome"
  make_adguard "$stage/AdGuardHome/AdGuardHome" "$version" "$accepts"
  ( cd "$stage" && tar -czf "$tgz" AdGuardHome )
  rm -rf "$stage"
}

setup_adguard() {
  local name="$1" archive="$2" behaviour="$3"
  W="$ROOT/$name"; rm -rf "$W"
  mkdir -p "$W"/{bin,lib/gateway,opt/AdGuardHome,repo}

  printf 'BOOTSTRAP_PROXY=""\n' > "$W/lib/gateway/env"
  cat > "$W/lib/gateway/net.sh" <<NET
gw_proxy() { printf ''; }
gw_curl() { "$W/bin/curl" "\$@"; }
NET
  printf 'bind_host: 0.0.0.0\n' > "$W/opt/AdGuardHome/AdGuardHome.yaml"
  printf '[adguard]\nversion = "v0.107.0"\n' > "$W/repo/versions.toml"

  cat > "$W/bin/curl" <<CURL
#!/bin/bash
out=""; url=""
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    -w) shift 2 ;;
    http*|https*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
case "\$url" in
  *checksums.txt) [ -f "$W/sums" ] && { cp "$W/sums" "\$out"; exit 0; }; exit 22 ;;
  */releases/latest) printf '%s' "https://example/tag/v0.108.0"; exit 0 ;;
  *.tar.gz) cp "$archive" "\$out"; exit 0 ;;
esac
exit 22
CURL
  chmod +x "$W/bin/curl"

  cat > "$W/bin/systemctl" <<SYSTEMD
#!/bin/bash
behaviour="$behaviour"
case "\$1 \$2" in
  "is-active --quiet")
    case "\$behaviour" in
      inactive) exit 3 ;;
      dies-after-start) [ -f "$W/started" ] && exit 3 || exit 0 ;;
      *) exit 0 ;;
    esac ;;
esac
case "\$1" in
  start|stop|restart)
    touch "$W/started"; echo "\$1 \$2" >> "$W/systemctl.log"
    [ "\$behaviour" = "start-fails" ] && [ "\$1" = start ] && exit 1
    exit 0 ;;
esac
exit 0
SYSTEMD
  chmod +x "$W/bin/systemctl"
}

run_adguard() {
  ( export PATH="$W/bin:$PATH" GW_LIB="$W/lib/gateway" \
           GW_ADGUARD_DIR="$W/opt/AdGuardHome" REPO="$W/repo"
    bash templates/lib/adguard-update.sh "$@" ) >"$W/out" 2>&1
}

adguard_version() {
  [ -x "$W/opt/AdGuardHome/AdGuardHome" ] \
    && "$W/opt/AdGuardHome/AdGuardHome" --version | grep -oE 'v[0-9.]+' || echo none
}

AG_GOOD="$ROOT/ag-good.tar.gz"; make_adguard_release "$AG_GOOD" "v0.108.0" yes
AG_BAD="$ROOT/ag-rejects.tar.gz"; make_adguard_release "$AG_BAD" "v0.108.0" no

echo
echo "== AdGuard: a version that rejects the current config is not installed =="
setup_adguard ag-reject "$AG_BAD" ok
make_adguard "$W/opt/AdGuardHome/AdGuardHome" "v0.107.0" yes
run_adguard v0.108.0
if grep -q 'rejects the current config' "$W/out" && [ "$(adguard_version)" = "v0.107.0" ]; then
  ok "aborts, and DNS keeps running on the old binary"
else
  bad "a config-rejecting AdGuard was installed: $(adguard_version)"
  sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== AdGuard: a checksum that does not match the pin aborts =="
setup_adguard ag-sum "$AG_GOOD" ok
make_adguard "$W/opt/AdGuardHome/AdGuardHome" "v0.107.0" yes
printf '[adguard]\nversion = "v0.108.0"\nsha256 = "%s"\n' \
  "0000000000000000000000000000000000000000000000000000000000000000" > "$W/repo/versions.toml"
run_adguard v0.108.0
if grep -q 'checksum mismatch' "$W/out" && [ "$(adguard_version)" = "v0.107.0" ]; then
  ok "aborts on a mismatched pin"
else
  bad "a mismatched checksum was accepted"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== AdGuard: a published checksum that disagrees aborts =="
setup_adguard ag-pub "$AG_GOOD" ok
make_adguard "$W/opt/AdGuardHome/AdGuardHome" "v0.107.0" yes
printf 'deadbeef  AdGuardHome_linux_amd64.tar.gz\n' > "$W/sums"
run_adguard v0.108.0
if grep -q 'published checksum does not match' "$W/out" && [ "$(adguard_version)" = "v0.107.0" ]; then
  ok "aborts when the published checksum disagrees"
else
  bad "a bad published checksum was accepted"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== AdGuard: a service that does not come back is rolled back =="
# DNS failing takes the LAN offline even though the tunnel is fine, and from a
# client it does not look like a DNS problem at all.
setup_adguard ag-rollback "$AG_GOOD" start-fails
make_adguard "$W/opt/AdGuardHome/AdGuardHome" "v0.107.0" yes
run_adguard v0.108.0
if grep -q 'rolling back' "$W/out" && [ "$(adguard_version)" = "v0.107.0" ]; then
  ok "rolls back to the version that was serving DNS"
else
  bad "a failed start left AdGuard on $(adguard_version)"; sed 's/^/      /' "$W/out" | tail -4
fi

echo
echo "== AdGuard: a clean update installs and keeps the previous binary =="
setup_adguard ag-happy "$AG_GOOD" ok
make_adguard "$W/opt/AdGuardHome/AdGuardHome" "v0.107.0" yes
run_adguard v0.108.0
if [ "$(adguard_version)" = "v0.108.0" ]; then
  ok "the new version is installed"
else
  bad "the update did not install: $(adguard_version)"; sed 's/^/      /' "$W/out" | tail -4
fi
[ -x "$W/opt/AdGuardHome/AdGuardHome.previous" ] \
  && ok "the previous binary is kept for a rollback" \
  || bad "no .previous was kept"

echo
echo "== AdGuard: the config it schema-migrates is never touched by the updater =="
# AdGuard owns that file. gw apply merges into it; the updater must not.
setup_adguard ag-conf "$AG_GOOD" ok
make_adguard "$W/opt/AdGuardHome/AdGuardHome" "v0.107.0" yes
printf 'bind_host: 0.0.0.0\nusers:\n  - name: admin\n' > "$W/opt/AdGuardHome/AdGuardHome.yaml"
before=$(sha256sum "$W/opt/AdGuardHome/AdGuardHome.yaml" | cut -d' ' -f1)
run_adguard v0.108.0
after=$(sha256sum "$W/opt/AdGuardHome/AdGuardHome.yaml" | cut -d' ' -f1)
[ "$before" = "$after" ] \
  && ok "AdGuardHome.yaml is untouched, admin password and all" \
  || bad "the updater rewrote AdGuard's own config"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
