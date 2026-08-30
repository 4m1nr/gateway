# Gateway

An HP thin client turned into a **selective transparent gateway**. Devices that
opt in point their default gateway at it, and everything they send is routed
through a remote Xray XHTTP tunnel — no per-app proxy settings, no client
software. The box's own traffic goes the same way, it serves filtered DNS to
the LAN, and it joins your tailnet as a subnet router and exit node.

```
                    ┌──────────────────────────── internet
              modem │
                │   │
             router/AP   (keeps DHCP; nothing changes here)
        ┌───────┼────────┬──────────────┬──────────────┐
        │       │        │              │              │
      phone    TV     laptop      thin client     tailnet peers
    gw=box  gw=router  gw=box       eth0 only      via tailscale0
```

Everything is generated from **one file**: `gateway.toml`. You never edit
configs on the box — you edit that file and run `gw apply`.

## Quick start

```bash
git clone <this repo> /opt/gateway && cd /opt/gateway
sudo scripts/00-bootstrap.sh # installs Go, builds bin/gw — then stops

gw init                      # interview; paste your share link
sudo scripts/00-bootstrap.sh # re-run: static IP, clock, logging
gw client add 192.168.1.50 laptop proxy
sudo scripts/10-xray.sh      # tunnel, verified over SOCKS before anything is intercepted
sudo scripts/20-adguard.sh   # LAN DNS
sudo scripts/30-tailscale.sh # subnet router + exit node
sudo scripts/40-web.sh       # dashboard (creates the service user + cert)
sudo scripts/50-hardening.sh # ssh, unattended upgrades, timers
sudo gw check                # prove the whole path end to end
```

`00-bootstrap.sh` runs twice, and stops the first time on purpose: the network
setup needs `net.static_ip` and `net.wan_if`, which `gw init` writes — and
`gw init` needs the binary the first run builds. Both runs are idempotent, so
re-running is the normal path rather than a recovery.

**If this box cannot reach the internet directly**, the first run has no config
to read a proxy from yet — that file does not exist until `gw init`. Pass it in
the environment for that one command:

```bash
sudo GW_PROXY=socks5h://127.0.0.1:1080 scripts/00-bootstrap.sh
```

Then put it in `gateway.toml` under `[bootstrap] socks_proxy` and every later
script picks it up on its own. See [Bootstrap proxy](#bootstrap-proxy).

Run the scripts in order. Each one leaves the box in a working state and tells you what to
verify before moving on — `10-xray.sh` confirms the tunnel over
SOCKS *before* any traffic is intercepted, so a bad XHTTP parameter can't take
the LAN offline.

## Opting a device in

**Set its default gateway to the box's IP, and its DNS to the same address.**

Both matter. DNS is not just for filtering: if a device keeps using the
router's resolver, blocked names come back as a private address, the device
sends traffic there, and the gateway drops it as unreachable. The symptom is
one site failing while everything else works.

The gateway redirects plain DNS that passes through it, so a device pointed at
a public resolver is covered automatically. A device pointed at the **router**
resolves over the local segment and never reaches the box at all — for those,
either set the DNS on the device, or set the router's DHCP to hand out the
box as the DNS server.

Nothing needs to be registered anywhere. The firewall's catch-all covers the
whole LAN, and only traffic that is actually being forwarded reaches it, so it
matches exactly the devices that pointed at the box. A device that never opts in
never sends a packet through it and is completely unaffected.

You only list a device to **override** that default:

```bash
gw client add 192.168.1.60 tv   direct   # forwarded untouched, real IP
gw client add 192.168.1.99 iot  block    # dropped at the gateway
sudo gw apply
```

Listed devices need a static IP or a DHCP reservation on the router, since the
override is keyed to the address. Change the default itself in `gateway.toml`:

```toml
[policy]
default = "proxy"   # or "direct" / "block"
```

### Profiles

A profile is a built-in policy **plus destination-specific exceptions** — for
sending work traffic through a work Xray server while everything else takes the
normal path:

```toml
[[upstream]]                       # a second Xray server
name = "work"
file = "outbounds/work.json"       # a full Xray outbound object

[[profile]]
name = "work-laptop"
base = "proxy"                     # unmatched traffic behaves like `proxy`

  [[profile.route]]
  via     = "work"                 # an upstream name, or proxy/direct/block
  domains = ["domain:corp.work.example"]
  ips     = ["10.20.0.0/16"]
```

```bash
gw client add 192.168.1.70 laptop work-laptop
sudo gw apply
```

Rules are matched most-specific-first, so a profile rule beats the global
domestic-direct split — work domains under `.ir` still reach the work upstream.
Xray takes the first matching rule, so that ordering *is* the behaviour, and
`tests/check_routing.py` asserts it.

**A profile device is always intercepted, even with `base = "direct"`** —
splitting traffic by destination requires Xray to see it. So it is fail-closed
like any proxied device: if the tunnel dies it loses connectivity rather than
falling back to a direct path. That is the cost of the split, not a bug.

See `docs/per-client-policy.md`.

## Commands

| | |
|---|---|
| `gw init` | interview → `gateway.toml`, parses a `vless://` link |
| `gw render` | generate `build/` (safe, changes nothing) |
| `gw diff` | show exactly what `apply` would change |
| `gw apply` | render, diff, install, validate, reload |
| `gw enable` | enable the whole stack to start on boot |
| `gw disable` | stop the stack and remove it from boot |
| `gw restart` | restart the whole stack |
| `gw status` | services, boot state, tunnel state, killswitch drop count |
| `gw check` | end-to-end verification incl. leak tests |
| `gw check --killswitch` | also prove traffic dies rather than leaking |
| `gw web` | run the dashboard (started by gw-web.service) |
| `gw client` | `list` / `add <ip> <name> <policy>` / `rm <ip>` |
| `gw job` | `list` / `add <name> <schedule>` / `rm` / `enable` / `disable` |
| `gw web-passwd` | set the dashboard password |
| `gw bench` | find the throughput bottleneck: link, CPU, or tunnel |
| `gw history [h] [ip]` | what happened while you weren't looking — for faults that come and go |
| `gw update` | `all` \| `services` \| `xray` \| `adguard` \| `tailscale` \| `geo` \| `packages` \| `--check` |
| `gw panic` | drop to plain NAT so the LAN works while you debug |
| `gw logs` | follow every relevant journal at once |

`gw apply` validates the nftables ruleset (`nft -c`) and the Xray config
(`xray -test`) **before** reloading anything. A config that would break the
gateway is refused rather than half-applied.

## Web dashboard

`https://<box>:8088` — tunnel state, services, per-route traffic, client
management, scheduled jobs, and the Xray configuration itself.

The **Xray** page puts the raw config in front of you. Outbounds are shown
exactly as the gateway loaded them, including the two fields it injects — `tag`,
which routing rules reference, and `streamSettings.sockopt.mark`, the loop guard
— because those are what make a pasted outbound safe to use here and they are
invisible in the file you pasted. Beside them is the complete generated
`config.json`, and a share-link importer for `vless://`, `vmess://`, `trojan://`
and `ss://` that writes nothing: the JSON appears for review before it becomes
the tunnel everything routes through.

```bash
sudo scripts/40-web.sh    # service user, self-signed cert, firewall rule
sudo gw web-passwd        # scrypt-hashed, stored outside the repo
```

It can rewrite the firewall, so it is fenced three independent ways:

1. **Source address** — nftables only accepts the port from `web.allow_cidrs`
   (default: your LAN plus the tailnet), and the app re-checks the peer itself.
   The address comes from the socket; `X-Forwarded-For` is ignored, because
   nothing proxies this service and a header claiming otherwise can only be a
   forgery.
2. **Password** — scrypt, with a per-address lockout after
   `max_failed_logins`. Sessions are bound to the address that created them, so
   a stolen cookie is not portable.
3. **Privilege separation** — the web process runs as `gwweb` and can do
   nothing on its own. Every privileged action is a JSON request piped to a
   single sudo entry point, `/usr/local/lib/gateway/gw-action`, which
   re-validates every field as root. The sudo grant is that one command with no
   arguments and no wildcards, and the request travels on stdin — so no value
   derived from an HTTP request ever reaches a command line, and a compromised
   web process cannot ask for anything the helper does not already implement.
   The password hash is `0600 root:root` and the web process never reads it —
   logins are verified across the same boundary.

   The one thing that is *not* a sudo grant is reading the journal: the
   dashboard streams logs, and a request/response helper cannot carry a stream,
   so `gwweb` is a member of `systemd-journal`. That is read-only access to logs
   the dashboard already reports on, with no path to escalation.

TLS is on by default with a self-signed certificate; your browser warns once.
That stops the password crossing the LAN in clear text, but a LAN attacker
could still substitute their own certificate and you would click through — if
that matters, reach the dashboard over Tailscale instead.

This is not exposed to the internet, and it is not built to be. Keep it that
way: don't port-forward it, and don't widen `allow_cidrs` to `0.0.0.0/0` (the
loader refuses that anyway).

## Updating

```bash
sudo gw update --check          # every component, changes nothing
sudo gw update xray             # newest release
sudo gw update xray v25.9.11    # a specific version
sudo gw update adguard          # AdGuard Home
sudo gw update tailscale        # via apt
sudo gw update geo              # geodata only
sudo gw update services         # geodata + Xray + AdGuard, no apt
sudo gw update                  # everything, then re-apply
```

### What updates on its own

| | schedule | set by |
|---|---|---|
| geodata (`.dat` files) | daily | `gw-geoupdate.timer` |
| Xray, AdGuard Home, geodata | weekly | `gw-update.timer`, `[system] auto_update` |
| OS security patches | daily | `unattended-upgrades`, `[system] unattended_upgrades` |
| Tailscale, other packages | never | run `sudo gw update tailscale` / `packages` |

`[system] auto_update` takes `off`, `check` (report only), `services` (the
default — geodata, Xray, AdGuard), or `all` (adds a full `apt upgrade` and a
re-apply). `auto_update_schedule` is any systemd `OnCalendar`, validated by
`gw apply` before it is installed, because an expression systemd cannot parse
produces a timer that loads and then never fires.

`services` is the default rather than `all` because each of those three tests
itself and rolls back if the new version will not start; an unattended
`apt upgrade` on the box the whole house routes through does not. Nothing
here reboots on its own — an unattended reboot takes the LAN's internet with
it.

Check that it is actually running:

```bash
systemctl list-timers 'gw-*'    # next and last run of each
journalctl -u gw-update         # what the last one did
```

An update that breaks the tunnel takes the whole LAN offline, so Xray and
AdGuard both go through the same guarded path:

1. downloads and verifies (a `sha256` pin in `versions.toml` if you set one,
   otherwise the published digest — which proves integrity, not authenticity)
2. runs the **new** binary against the **live** config with `-test`, and
   aborts without touching `/usr/local/bin` if it is rejected
3. keeps the old binary at `xray.previous` and rolls back to it if the service
   fails to start or does not stay up

The same scripts do the first install, so there is one code path to trust
rather than two that drift apart.

Geodata pulls **every `.dat` asset** from the latest release of a configurable
repo, so a new rule file appearing upstream arrives on its own:

```toml
[geodata]
repo = "Chocolate4U/Iran-v2ray-rules"
```

The installed release tag is recorded, so the **daily** timer is a cheap no-op
until upstream actually publishes. Downloads are size-checked and tested against
the live Xray config before they replace anything, with rollback if that fails —
a truncated `.dat` takes the tunnel down, and this runs unattended.

Naming `files = ["geoip", "geosite"]` pins the set instead, fetched through
`url_template` (`{0}` is each file name) with release discovery skipped.

## Bootstrap proxy

Setup happens before the tunnel exists, so a box that cannot reach the internet
directly has a chicken-and-egg problem: it needs the internet to install the
thing that gives it the internet.

There is a second turn of the same screw, and it decides how this is
configured: the proxy setting lives in `gateway.toml`, which `gw init` writes —
and `gw init` is a command in a binary the first bootstrap run builds. So on a
first install there is no config to read a proxy out of yet.

**Where each stage reads it from:**

| when | source |
|---|---|
| first `00-bootstrap.sh` — packages and the build | `GW_PROXY` in the environment, and nothing else |
| after `gw init`, every later script | `bootstrap.socks_proxy` in `gateway.toml` |
| any command, at any time | `gw --proxy ...` or `GW_PROXY=...`, which override both |
| once the tunnel is up | nothing — see below |

So a first install behind a proxy starts like this:

```bash
sudo GW_PROXY=socks5h://127.0.0.1:1080 scripts/00-bootstrap.sh
```

and after `gw init` has written the config, the setting carries the rest:

```toml
[bootstrap]
socks_proxy = "socks5h://127.0.0.1:1080"
```

Every download the setup and update paths make goes through one helper, so this
single setting covers Xray, AdGuard, geodata and apt. Prefer `socks5h://` so
DNS is resolved at the proxy rather than locally.

**It stops being used the moment the tunnel works.** Once the watchdog reports a
working tunnel, the box's own traffic is already routed through Xray by the
OUTPUT chain — sending a download through the proxy as well would push it out
through a tunnel that is already carrying it, and would fail outright on a box
whose bootstrap proxy has since been shut down. You do not need to clear the
setting by hand; it is ignored while the tunnel is up, and used again if the
tunnel goes down and something needs fetching. An explicit `gw --proxy` still
wins either way, because passing it is a statement of intent.

The apt proxy in particular is written and removed around the commands that
need it, rather than left in `/etc/apt/apt.conf.d` where it would break apt the
day the bootstrap proxy goes away.

## Custom routing

Extra Xray routing rules spliced into the generated pipeline. A TOML table maps
one-to-one onto Xray's rule JSON, so the table *is* the rule — `position` is the
only key the gateway consumes:

```toml
[[route]]                          # nothing reaches this host on SSH, ever
position    = "first"
ip          = ["203.0.113.5/32"]
port        = "22"
outboundTag = "block"

[[route]]                          # force an intranet name direct
domain      = ["domain:intranet.example.com"]
outboundTag = "direct"

[[route]]                          # a whole network via the work upstream
ip          = ["198.51.100.0/24"]
outboundTag = "work"
```

| `position` | lands |
|---|---|
| `first` | ahead of everything, including per-client policy — where a hard block belongs |
| `before` (default) | after per-client policy, ahead of the geo split, so it beats "all `.ir` goes direct" |
| `after` | after the geo split, before the fallthrough defaults |

`outboundTag` accepts an `[[upstream]]` name as well as `proxy`/`direct`/`block`.
A `json = """..."""` key takes a raw rule for anything the TOML form cannot
express. `tests/check_custom_routes.py` asserts each rule lands where it asked
to — misplacement produces no error, just a rule that quietly stops applying.

## Scheduled jobs

Bash on a cron schedule, from the CLI or the dashboard:

```bash
gw job add nightly-backup "0 4 * * *" --file backup.sh --desc "config backup"
echo 'tailscale status' | gw job add tsping @hourly --user nobody -
gw job list
gw job disable nightly-backup
sudo gw apply
```

Jobs are stored in `gateway.toml` like everything else, so a rebuilt box comes
back with them. They render to `/etc/cron.d/gw-jobs`, with each script in its
own file under `/usr/local/lib/gateway/jobs/`.

That split is not cosmetic: **cron treats `%` in a crontab line as a newline**
and silently truncates there, so a `curl -w '%{time_total}'` one-liner in a
crontab quietly becomes a different command. Keeping the crontab to a single
"run this script" line makes that impossible, and a test asserts no `%` ever
reaches it.

Scripts are stored as TOML *literal* strings so backslash continuations and
`\n` survive verbatim. Output goes to the journal (`gw logs`), because a box
with no MTA silently discards what cron would otherwise mail.

⚠️ **Jobs run as root unless `user` says otherwise.** The dashboard's job editor
is therefore the most powerful thing on the box — anyone who gets past the login
can run arbitrary code as root. That is inherent to the feature, not a flaw in
it, but it means the dashboard password is a root password. Set `[web] enabled =
false` if you would rather not have that reachable over the network.

## Starting on boot

Everything is tied together by a single unit, `gateway.target`:

```bash
systemctl status gateway.target            # is the stack up?
systemctl list-dependencies gateway.target # what's in it
sudo gw restart                            # restart the whole stack
sudo gw enable                             # make it all start at boot
```

`gw apply` enables it for you, so a normal install needs none of this. Each
member declares `PartOf=gateway.target`, which is what makes
`systemctl restart gateway.target` propagate to all of them.

Boot order matters here and is enforced:

1. **`gw-network.service`** — policy routing and the firewall, pulled in from
   `sysinit.target` and ordered before `network-pre.target`, the same way
   Debian's own `nftables.service` is. There is no window during boot where
   forwarding is unfiltered.
2. **`chrony-wait.service`** — holds `time-sync.target` until the clock is
   actually correct. Thin clients often have a flat CMOS battery and boot years
   out of date; TLS and REALITY both fail on skew, so without this the tunnel
   fails on every cold boot until chrony catches up.
3. **`xray.service`** — ordered after `time-sync.target` and `network-online`,
   and `Requires=gw-network.service`.
4. **`AdGuardHome.service`** — ordered after Xray via a drop-in. Its upstream
   DoH rides the tunnel, so starting first means a burst of failed lookups —
   and a resolver that caches those failures serves them to the LAN until the
   negative TTL expires.

`tailscaled` is *Wanted* by the target but deliberately **not** `PartOf` it, so
`gw restart` can't drop the Tailscale session you're using to run it.

Every dependency is `Wants=`, never `Requires=`: a failed AdGuard shouldn't
take the tunnel down, and a failed tunnel shouldn't stop DNS from serving the
LAN.

`gw check` verifies boot configuration as a separate section — "it works right
now" and "it comes back after a power cut" are different claims.

## Outbounds are Xray's own JSON

Every server — the main tunnel, the fallback, and each profile upstream — is a
**complete Xray outbound object**, used verbatim:

```toml
[xray.outbound]
file = "outbounds/main.json"       # or: json = """ { ... } """
server_ip = ""                     # optional: pin the IP, skip DNS at boot
```

```json
{
  "protocol": "vless",
  "settings": { "vnext": [ { "address": "example.com", "port": 443,
    "users": [ { "id": "...", "encryption": "none" } ] } ] },
  "streamSettings": {
    "network": "xhttp", "security": "tls",
    "tlsSettings": { "serverName": "example.com", "alpn": ["h2"] },
    "xhttpSettings": { "host": "example.com", "path": "/xhttp", "mode": "auto" }
  }
}
```

The gateway does not model protocols or transports, so anything Xray supports
works — VLESS/XHTTP, Reality, Trojan, Shadowsocks, a chained outbound — without
this repo needing to learn about it. `gw init` still writes the file for you
from a `vless://` share link.

Two fields are always overridden, because the gateway depends on them and
nobody writing an outbound by hand would include them:

| field | why |
|---|---|
| `tag` | routing rules reference outbounds by name |
| `streamSettings.sockopt.mark` | the loop guard — an outbound without it makes Xray's own packets eligible for TPROXY, and the box deadlocks the moment interception is enabled |

A mark that conflicts with `xray.outbound_mark` is rejected at load rather than
silently overwritten, and `tests/check_outbounds.py` asserts that every
generated outbound is tagged and marked. That is the highest-consequence check
in the suite.

Credentials live in `outbounds/*.json`, which is gitignored — only
`*.example.json` is committed.

## How it works

Two layers decide what happens to a packet:

| Layer | Decides |
|---|---|
| nftables | *whether* a client is intercepted — listed overrides first, then a LAN-wide catch-all |
| Xray routing | *where* an intercepted flow goes — profile exceptions, then the geo split, then the profile's base |

**Interception.** `prerouting` checks the explicit override sets first, then
falls through to a catch-all on the LAN CIDR. It matches traffic and hands
it to Xray's `dokodemo-door` listener with TPROXY. A `divert` chain re-marks
packets belonging to established transparent sockets, and a policy-routing rule
(`fwmark 1` → a table whose only route is `local default dev lo`) makes the
kernel deliver them locally instead of forwarding them.

**The box's own traffic.** The `output` chain marks locally-generated packets
the same way. Xray's own sockets are exempted twice over — every outbound sets
`SO_MARK`, and the chain also returns early on the `xray` uid. Without those
guards the box would route its own tunnel traffic back into the tunnel.

**Fail-closed.** The `forward` chain has no accept path for `@proxy_clients`.
If Xray isn't listening, TPROXY doesn't match, and the packet reaches a terminal
drop. There is no fallback to leak through, because there is no fallback.

**Split routing.** TPROXY only hands Xray a destination IP, so the inbound
sniffs HTTP/TLS/QUIC to recover hostnames; `geosite:category-ir` and `geoip:ir`
then go direct while everything else takes the tunnel. `gw check` proves this
using Xray's stats API rather than inferring it.

**DNS.** AdGuard Home serves the LAN. Its upstream DoH is captured by the
`output` chain like any other local process, so it resolves through the tunnel;
`.ir` names go to domestic resolvers directly. Upstreams must be IP literals —
a hostname there would need DNS to resolve the DNS server.

**Tailscale.** Exit-node traffic is routed by `tailscale.exit_node_policy`,
which takes any policy or profile name — so a phone abroad can exit through your
main tunnel, go direct, be blocked, or get a profile's full rule set (reaching
the work upstream exactly like the work laptop does). `tailscaled`'s own
control-plane traffic is tunnelled too (useful where Tailscale is blocked) —
with a **lifeline**: if the tunnel stays down past `lifeline_after_min`, the
watchdog lets tailscaled talk direct so you don't lose remote access exactly
when you need it. Client traffic stays fail-closed regardless.

## Things worth knowing

- **IPv6 is off**, on the router and on `eth0`. A client's v6 default route
  comes from Router Advertisements, not from the gateway setting you configure
  per device — so a dual-stacked client would keep using the router for v6 and
  bypass the tunnel silently. Disabling it removes the leak path. It's disabled
  per-interface, not kernel-wide: Tailscale needs v6 for its own addressing.
- **The clock is load-bearing.** TLS and REALITY both fail on skew, and it looks
  like a broken tunnel. NTP is pinned to a direct path so time sync can never
  depend on the tunnel.
- **Single NIC** means bypassed traffic hairpins through one port. Fine at home
  speeds; ICMP redirects are disabled so clients can't be told to skip the box.
- **AdGuard's admin password** is the one thing not managed here — a password
  hash doesn't belong in a git repo. Set it in the web UI; `gw apply` leaves it
  and anything else you set there alone.

## Layout

```
gateway.toml          the source of truth (gitignored)
gateway.example.toml  documented template
outbounds/*.json      Xray outbound objects, used verbatim (gitignored)
versions.toml         pinned Xray / AdGuard versions + checksums
bin/gw                the binary (built; gitignored)
cmd/gw/               the CLI
internal/config/      gateway.toml model and validation
internal/render/      every generated file
internal/apply/       diff, validate, install, reload
internal/web/         the dashboard's server and privilege boundary
dashboard/            the dashboard's source (React); dist/ is committed
internal/check/       `gw check` — end-to-end verification
internal/diag/        status, diag, trace, history, bench
templates/            nftables, systemd units, runtime helper scripts
scripts/              ordered, idempotent install steps
vendor/               vendored Go dependencies, so the box builds offline
build/                rendered output, mirrors the target filesystem
tests/                fixtures, frozen golden output, and run.sh for the shell
docs/                 recovery, troubleshooting, per-client policy
```

The gateway is a single static Go binary. Dependencies are vendored, so a box
with no working internet — the normal state of a gateway being repaired — can
still build the thing that fixes it:

```bash
make build     # CGO_ENABLED=0, no network needed
make check     # vet, gofmt, the full suite
make offline   # proves the build needs no network
```

The dashboard is built with Node and its output is committed, so the box never
needs a JavaScript toolchain; CI rebuilds it and fails if the committed output
does not match its source.

`go test ./...` runs anywhere, without root or a network. It compares every
generated file against output frozen from before the Go migration, feeds every
ruleset to a real `nft -c` inside a user namespace, and asserts the firewall
and routing invariants one at a time. `tests/run.sh` covers what is still
shell — the install scripts and the runtime helpers — and runs the Go suite
first.
