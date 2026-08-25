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
sudo scripts/50-hardening.sh # ssh, unattended upgrades, timers
sudo gw check                # prove the whole path end to end
```

Run the scripts in order. Each one leaves the box in a working state and tells
you what to verify before moving on — `10-xray.sh` confirms the tunnel over
SOCKS *before* any traffic is intercepted, so a bad XHTTP parameter can't take
the LAN offline.

## Opting a device in

Set its default gateway to the box's IP and its DNS to the same address, then
tell the gateway about it:

```bash
gw client add 192.168.1.50 laptop proxy    # through the tunnel
gw client add 192.168.1.60 tv     direct   # forwarded untouched
gw client add 192.168.1.99 iot    block    # dropped
sudo gw apply
```

Give opted-in devices a static IP or a DHCP reservation on the router — the
policy is keyed to the address. Devices you never touch keep using the router
and are completely unaffected. See `docs/per-client-policy.md`.

## Commands

| | |
|---|---|
| `gw init` | interview → `gateway.toml`, parses a `vless://` link |
| `gw render` | generate `build/` (safe, changes nothing) |
| `gw diff` | show exactly what `apply` would change |
| `gw apply` | render, diff, install, validate, reload |
| `gw status` | services, tunnel state, killswitch drop count |
| `gw check` | end-to-end verification incl. leak tests |
| `gw check --killswitch` | also prove traffic dies rather than leaking |
| `gw client` | `list` / `add <ip> <name> <policy>` / `rm <ip>` |
| `gw update` | binaries, geodata, blocklists, then re-apply |
| `gw panic` | drop to plain NAT so the LAN works while you debug |
| `gw logs` | follow every relevant journal at once |

`gw apply` validates the nftables ruleset (`nft -c`) and the Xray config
(`xray -test`) **before** reloading anything. A config that would break the
gateway is refused rather than half-applied.

## How it works

Two layers decide what happens to a packet:

| Layer | Decides |
|---|---|
| nftables sets | *whether* a client is intercepted |
| Xray routing | *where* an intercepted flow goes (proxy / direct / block) |

**Interception.** `prerouting` matches traffic from `@proxy_clients` and hands
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
lib/                  config model, renderers (Python 3, stdlib only)
templates/            nftables, systemd units, helper scripts
scripts/              ordered, idempotent install steps
build/                rendered output, mirrors the target filesystem
tests/run.sh          offline suite — validates every ruleset with real `nft -c`
docs/                 recovery, troubleshooting, per-client policy
```

`tests/run.sh` runs anywhere, without root or a network, and feeds every
generated ruleset to a real `nft -c` inside a user namespace. Run it after any
change to `lib/` or `templates/`.
