#!/usr/bin/env bash
# cleanup.sh against a scratch checkout.
#
# The script deletes things on a box that the whole office routes through, and
# its one safety property is that it never removes anything git tracks — the
# deployment is a checkout, and a dirty worktree is a box that cannot take the
# next fix. That property is not something a grep can confirm, so this builds a
# repo-shaped tree, runs the real script against it, and looks at what is left.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
REPO_ROOT="$PWD"

PASS=0; FAIL=0
c_red=$'\033[31m'; c_grn=$'\033[32m'; c_off=$'\033[0m'
ok()  { printf '  %s\xe2\x9c\x93%s %s\n' "$c_grn" "$c_off" "$*"; PASS=$((PASS+1)); }
bad() { printf '  %s\xe2\x9c\x97%s %s\n' "$c_red" "$c_off" "$*"; FAIL=$((FAIL+1)); }

if ! command -v git >/dev/null 2>&1; then
  printf '  - git is not installed; skipping\n'
  printf '0 passed, 0 failed\n'
  exit 0
fi

# scratch_repo — a checkout shaped like a deployment, printed on stdout.
scratch_repo() {
  local dir; dir=$(mktemp -d)
  mkdir -p "$dir"/{lib,scripts,docs,vendor/x,build/etc,bin,outbounds,dashboard/dist,dashboard/node_modules/pkg,tests}
  cp "$REPO_ROOT/lib/common.sh"        "$dir/lib/common.sh"
  cp "$REPO_ROOT/scripts/cleanup.sh"   "$dir/scripts/cleanup.sh"

  # Tracked: everything a `git pull` would expect to find unchanged.
  echo "docs"            > "$dir/docs/recovery.md"
  echo "vendored module" > "$dir/vendor/x/x.go"
  echo "built asset"     > "$dir/dashboard/dist/index.html"
  echo "example"         > "$dir/outbounds/main.example.json"
  echo "tests"           > "$dir/tests/run.sh"

  git -C "$dir" init -q
  git -C "$dir" config user.email t@example.invalid
  git -C "$dir" config user.name  t
  git -C "$dir" add -A -- lib scripts docs vendor dashboard/dist outbounds tests
  git -C "$dir" commit -qm "scratch"

  # Untracked: what the box accumulates, and what the config and credentials
  # look like once it is actually deployed.
  echo "node dep"        > "$dir/dashboard/node_modules/pkg/index.js"
  echo "editor leftover" > "$dir/notes.bak"
  echo "merge leftover"  > "$dir/scripts/10-xray.sh.orig"
  echo "binary"          > "$dir/bin/gw"
  echo "[net]"           > "$dir/gateway.toml"
  echo "{}"              > "$dir/outbounds/main.json"
  echo "rendered"        > "$dir/build/etc/rendered.conf"
  printf '%s' "$dir"
}

run_cleanup() {
  local dir="$1"; shift
  GW_REPO="$dir" GW_YES=1 bash "$dir/scripts/cleanup.sh" "$@" 2>&1
}

echo "== a dry run changes nothing =="
dir=$(scratch_repo)
before=$(find "$dir" -path "$dir/.git" -prune -o -print | sort | md5sum)
run_cleanup "$dir" --dry-run >/dev/null
after=$(find "$dir" -path "$dir/.git" -prune -o -print | sort | md5sum)
[ "$before" = "$after" ] \
  && ok "--dry-run left every path in place" \
  || bad "--dry-run modified the tree"
rm -rf "$dir"

echo
echo "== the real run =="
dir=$(scratch_repo)
out=$(run_cleanup "$dir")

# What must go.
[ ! -e "$dir/dashboard/node_modules" ] \
  && ok "dashboard/node_modules removed" \
  || bad "dashboard/node_modules survived — the one thing worth removing"
[ ! -e "$dir/notes.bak" ] \
  && ok "an untracked .bak removed" \
  || bad "notes.bak survived"
[ ! -e "$dir/scripts/10-xray.sh.orig" ] \
  && ok "an untracked .orig removed" \
  || bad "10-xray.sh.orig survived"

# What must stay, and why each one matters.
for pair in \
  "docs/recovery.md|tracked, and a pull would restore it anyway" \
  "vendor/x/x.go|the box builds -mod=vendor with no network" \
  "dashboard/dist/index.html|embedded into bin/gw at compile time" \
  "tests/run.sh|tracked" \
  "bin/gw|the running binary" \
  "gateway.toml|the config" \
  "outbounds/main.json|the credentials" \
  "build/etc/rendered.conf|regenerated, but removing it frees nothing"
do
  path="${pair%%|*}"; why="${pair#*|}"
  [ -e "$dir/$path" ] \
    && ok "kept $path ($why)" \
    || bad "REMOVED $path — $why"
done

echo
echo "== the checkout is still clean afterwards =="
# The headline invariant. A single deleted tracked file shows up here, and on a
# real box it is the difference between `git pull` working and not.
status=$(git -C "$dir" status --porcelain -- docs vendor dashboard/dist tests lib scripts)
if [ -z "$status" ]; then
  ok "git reports no changes to anything it tracks"
else
  bad "the checkout is dirty after cleanup:"
  printf '%s\n' "$status" | sed 's/^/      /'
fi
rm -rf "$dir"

echo
echo "== a tracked path offered up is refused, not deleted =="
# The guard itself, exercised directly: point the script at a target that is
# tracked and confirm it declines rather than obeying.
dir=$(scratch_repo)
sed -i 's|^consider dashboard/node_modules|consider docs "probe"\nconsider dashboard/node_modules|' \
  "$dir/scripts/cleanup.sh"
out=$(run_cleanup "$dir")
if printf '%s' "$out" | grep -q "keeping docs"; then
  ok "a tracked target is skipped with a reason"
else
  bad "the tracked-path guard did not fire"
fi
[ -e "$dir/docs/recovery.md" ] \
  && ok "and the tracked target is still there" \
  || bad "a tracked target was deleted despite the guard"
rm -rf "$dir"

echo
echo "== the shared Go caches need asking for =="
# They are per-user and shared with every other Go project that account builds.
# Removing them by default would be correct on the box and destructive on the
# workstation someone develops from.
dir=$(scratch_repo)
out=$(run_cleanup "$dir" --dry-run)
if command -v go >/dev/null 2>&1; then
  if printf '%s' "$out" | grep -q 'pass --go-cache'; then
    ok "the Go caches are named but not removed without --go-cache"
  else
    bad "the Go caches are not reported as an opt-in"
  fi
else
  printf '  - go is not installed; skipping\n'
fi
rm -rf "$dir"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
