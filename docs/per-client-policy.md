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

## Different routing per client

The current design gives every proxied client the same split. To send one client
through a different outbound, add a `source`-matched rule ahead of the geo rules
in `lib/xray_config.py`'s `_routing()` — Xray sees the real client IP because
`dokodemo-door` preserves it. That's a code change, not a config toggle; it was
left out until there's a concrete need for it.
