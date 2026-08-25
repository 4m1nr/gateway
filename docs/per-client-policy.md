# Per-client policy

## The two layers

```
packet from 192.168.1.50
   │
   ├─ nftables: is 192.168.1.50 in @proxy_clients?
   │     no  → forwarded normally, or dropped by the killswitch
   │     yes → TPROXY to Xray
   │
   └─ Xray routing: where does this flow go?
         geosite:category-ir / geoip:ir → direct
         everything else                → the tunnel
```

nftables decides *whether* to intercept. Xray decides *where* an intercepted
flow goes. A `direct` client never reaches Xray at all.

## Policies

| policy | effect |
|---|---|
| `proxy` | intercepted; split routing applies |
| `direct` | forwarded straight to the router, never touched |
| `block` | dropped at the gateway |

`default_policy` applies to a device that uses the box as its gateway without
being listed. It defaults to `proxy`, which is the safe direction: an unknown
device gets the tunnel and the killswitch, never a silent direct path.

## Managing clients

```bash
gw client list
gw client add 192.168.1.50 laptop proxy
gw client add 192.168.1.60 tv     direct
gw client rm  192.168.1.60
sudo gw apply
```

`gw client add` on an existing IP replaces that entry.

## Addresses have to be stable

Policy is keyed to the IP. Since the router still runs DHCP, give each opted-in
device either a static address or a DHCP reservation in the router's UI. A
device whose address moves silently inherits whatever policy the new address
has — including `default_policy`.

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
