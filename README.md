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
sudo ln -s /opt/gateway/bin/gw /usr/local/bin/gw

gw init                      # interview; paste your vless:// XHTTP link
gw client add 192.168.1.50 laptop proxy

sudo scripts/00-bootstrap.sh # base system, static IP, clock, logging
sudo scripts/10-xray.sh      # tunnel, verified over SOCKS before anything is intercepted
sudo scripts/20-adguard.sh   # LAN DNS
sudo scripts/30-tailscale.sh # subnet router + exit node
sudo scripts/40-web.sh       # dashboard (creates the service user + cert)
sudo scripts/50-hardening.sh # ssh, unattended upgrades, timers
sudo gw check                # prove the whole path end to end
```

Run the scripts in order. Each one leaves the box in a working state and tells
you what to verify before moving on — `10-xray.sh` confirms the tunnel over
SOCKS *before* any traffic is intercepted, so a bad XHTTP parameter can't take
the LAN offline.

## Opting a device in

**Set its default gateway to the box's IP.** That's the whole procedure — the
device is now proxied, split-routed and covered by the kill switch. Point its
DNS at the same address to get filtering too.

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
name    = "work"
address = "vpn.work.example"
uuid    = "..."
path    = "/xhttp"

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
| `gw client` | `list` / `add <ip> <name> <policy>` / `rm <ip>` |
| `gw web-passwd` | set the dashboard password |
| `gw update` | binaries, geodata, blocklists, then re-apply |
| `gw panic` | drop to plain NAT so the LAN works while you debug |
| `gw logs` | follow every relevant journal at once |

`gw apply` validates the nftables ruleset (`nft -c`) and the Xray config
(`xray -test`) **before** reloading anything. A config that would break the
gateway is refused rather than half-applied.

## Web dashboard

`https://<box>:8088` — tunnel state, services, per-route traffic, an on-demand
exit-IP check, and client management with an Apply button.

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
   single sudo entry point, `web-action.py`, which re-validates every field as
   root. The sudo grant is that one command with no arguments and no wildcards,
   so a compromised web process cannot ask for anything the helper does not
   already implement. The password hash is `0600 root:root` and the web process
   never reads it — logins are verified across the same boundary.

TLS is on by default with a self-signed certificate; your browser warns once.
That stops the password crossing the LAN in clear text, but a LAN attacker
could still substitute their own certificate and you would click through — if
that matters, reach the dashboard over Tailscale instead.

`http.server` is not a hardened internet-facing server, and this is not exposed
to the internet. Keep it that way: don't port-forward it, and don't widen
`allow_cidrs` to `0.0.0.0/0` (the loader refuses that anyway).

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

**Tailscale.** `100.64.0.0/10` is in `@proxy_clients`, so exit-node traffic goes
through Xray: a phone abroad exits from your Xray server. `tailscaled`'s own
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
versions.toml         pinned Xray / AdGuard versions + checksums
bin/gw                the CLI
lib/                  config model, renderers, dashboard (Python 3, stdlib only)
templates/            nftables, systemd units, helper scripts, web assets
scripts/              ordered, idempotent install steps
build/                rendered output, mirrors the target filesystem
tests/run.sh          offline suite — validates every ruleset with real `nft -c`
docs/                 recovery, troubleshooting, per-client policy
```

`tests/run.sh` runs anywhere, without root or a network, and feeds every
generated ruleset to a real `nft -c` inside a user namespace. Run it after any
change to `lib/` or `templates/`.
