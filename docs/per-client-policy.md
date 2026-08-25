# Per-client policy

## Opting in is one step

Set a device's default gateway to the box. That is all — it is proxied from
that moment, with no entry anywhere.

This works because the catch-all rule matches the whole LAN, and `prerouting`
only ever sees traffic that is *being forwarded*. A device using the router as
its gateway never sends the box a packet, so a LAN-wide rule and a
device-by-device opt-in come to the same thing — without the bookkeeping.

## The two layers

```
packet from 192.168.1.50 (arriving because it set us as its gateway)
   │
   ├─ nftables, in order:
   │     in @blocked_clients?  → drop
   │     in @direct_clients?   → forward untouched
   │     in @proxy_clients?    → TPROXY to Xray
   │     is it the box or the router? → leave alone
   │     otherwise, in the LAN? → [policy].default   ← the catch-all
   │
   └─ Xray routing: where does this flow go?
         geosite:category-ir / geoip:ir → direct
         everything else                → the tunnel
```

nftables decides *whether* to intercept. Xray decides *where* an intercepted
flow goes. A `direct` client never reaches Xray at all.

The listed sets are checked before the catch-all, so an override always wins
regardless of what the default is.

## Policies

| policy | effect |
|---|---|
| `proxy` | intercepted; split routing applies |
| `direct` | forwarded straight to the router, never touched |
| `block` | dropped at the gateway |
| *profile name* | intercepted; the profile's own rules apply first (see below) |

## The default

```toml
[policy]
default = "proxy"
```

Applies to every device that uses the box as its gateway and is not listed.
`proxy` is the safe direction: an unknown device gets the tunnel and the kill
switch, never a silent direct path.

Under a `proxy` default the LAN is deliberately **not** masqueraded — there is
no NAT path for it to fall back to, which is what keeps fail-closed honest.
Under `direct` the catch-all forwards and masquerades instead.

It must live in the `[policy]` table. A bare `default_policy = ...` written
after any other `[table]` is parsed by TOML as a key *of that table* and is
silently ignored; the loader now rejects that rather than quietly using the
wrong policy.

## Managing clients

```bash
gw client list
gw client add 192.168.1.50 laptop proxy
gw client add 192.168.1.60 tv     direct
gw client rm  192.168.1.60
sudo gw apply
```

`gw client add` on an existing IP replaces that entry.

## Addresses have to be stable — for overrides only

Overrides are keyed to the IP, so a listed device needs a static address or a
DHCP reservation in the router's UI. If its address moves, it silently falls
back to `[policy].default`.

Devices you have not listed need nothing: the catch-all covers the whole LAN,
so a proxied-by-default device can take any address the router hands it.

Addresses are validated at render time: an IP outside `lan_cidr`, a duplicate,
or the router's own address is refused rather than rendered into a ruleset.

## Tailnet traffic

`100.64.0.0/10` is added to `@proxy_clients` when
`tailscale.proxy_tailnet_egress = true`, so anything using this box as its
Tailscale exit node is proxied like a LAN client. Set it to `false` and exit-node
traffic goes out through your ISP instead.

## Profiles

A profile says: *behave like `base`, except send these destinations somewhere
else.* The motivating case is a work laptop whose corporate ranges and domains
must go through a work Xray server while the rest of its traffic takes the
normal tunnel.

```toml
[[upstream]]
name    = "work"
address = "vpn.work.example"
port    = 443
uuid    = "..."
path    = "/xhttp"
security = "tls"

[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via     = "work"
  domains = ["domain:corp.work.example", "domain:jira.work.example"]
  ips     = ["10.20.0.0/16", "203.0.113.0/24"]

  [[profile.route]]
  via     = "block"
  domains = ["geosite:category-ads-all"]

[[client]]
ip     = "192.168.1.70"
name   = "work-laptop"
policy = "work-laptop"
```

`via` accepts any `[[upstream]]` name plus the three built-in targets
(`proxy`, `direct`, `block`), so a profile can force something through the main
tunnel, force it direct, or drop it — per device.

`base` is `proxy` or `direct` only. A `block` base would leave nothing to route.

### Rule order is the behaviour

Xray takes the first matching rule. The generated order is:

```
1. blocked clients
2. direct clients
3. profile exceptions          ← most specific
4. global geo split (.ir direct)
5. profile fallthrough (base)
6. global default
```

Exceptions sit **above** the geo split so `corp.example.ir` still reaches the
work upstream instead of losing to "all `.ir` goes direct". The fallthrough sits
**below** it so a profile client keeps normal domestic-direct routing for
everything its own rules didn't claim.

`tests/check_routing.py` asserts both relative positions, because getting this
wrong produces no error — just traffic quietly leaving by the wrong door.

### Profiles are always intercepted

Even with `base = "direct"`. Splitting by destination requires Xray to see the
traffic — domain rules need the TLS SNI, which only sniffing recovers. So a
profile device behaves like a proxied one for kill-switch purposes: if the
tunnel is down it loses connectivity rather than falling back to a direct path.

If you want a device that is genuinely untouched, use `policy = "direct"`; it
never reaches Xray at all.

### Naming

Profile and upstream names share one namespace and become Xray outbound tags:
lowercase letters, digits and dashes, up to 24 characters. `proxy`, `direct` and
`block` are reserved.
