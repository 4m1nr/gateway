# Troubleshooting

Start with `sudo gw check` — it isolates which stage is broken. What follows is
symptom → cause, ordered by how often each one is actually the problem.

## The tunnel won't come up at all

**Check the clock first.** `date -u`, then `chronyc tracking`. TLS and REALITY
both fail on skew and the symptom looks exactly like a broken tunnel or wrong
credentials. NTP is pinned to a direct path precisely so this is fixable
without the tunnel.

Then the XHTTP parameters. They must match the server exactly:

| `gateway.toml` | must match the server's |
|---|---|
| `path` | XHTTP path |
| `host` | `Host` header the server/CDN expects |
| `mode` | `auto` / `packet-up` / `stream-up` / `stream-one` |
| `alpn` | what the fronting proxy negotiates |
| `sni` | certificate name |

`journalctl -u xray -n 50` shows the handshake failure. A CDN or reverse proxy
in front of the server that doesn't pass the path through unchanged is a common
cause; so is `h2` in `alpn` when the front only speaks HTTP/1.1.

## First packet works, then the connection hangs

The `divert` chain is missing or not matching. `nft list chain inet gateway
divert` should show a `socket transparent 1` rule. Without it, only the first
packet of each connection is delivered to the transparent socket.

## The box wedges the moment interception is enabled

A routing loop: Xray's own traffic is being captured and fed back to Xray. Both
guards must be present in the `output` chain:

```bash
nft list chain inet gateway output | grep -E 'MARK_XRAY|skuid'
```

and every Xray outbound must carry `"mark": 255` in `streamSettings.sockopt`.
`tests/run.sh` asserts both.

## A proxied client has no internet

That is the kill switch, and it means Xray isn't listening:

```bash
gw status
ss -lnt sport = :12345
nft list chain inet gateway forward | grep killswitch   # drop counter climbing
```

Fix the tunnel; the client recovers on its own.

## Everything is slow, or large pages hang

MSS clamping isn't applying, or the path MTU is smaller than assumed. The
`forward` chain clamps to PMTU; check with
`nft list chain inet gateway forward | grep maxseg`. `tcp_mtu_probing` is
already on.

## Domestic sites are slow or go through the tunnel

The split isn't matching. `gw check` reports which outbound a domestic request
actually used. If it went through the tunnel:

```bash
ls -la /usr/local/share/xray/          # geoip.dat / geosite.dat present and recent?
sudo /usr/local/lib/gateway/geoupdate.sh
```

Sniffing must also be working — domain rules can't match without it, since
TPROXY only supplies an IP.

## DNS doesn't work for clients

```bash
dig @192.168.1.2 example.com
systemctl status AdGuardHome
ss -lnup sport = :53
```

If port 53 is taken, `systemd-resolved`'s stub listener is still running —
`scripts/20-adguard.sh` disables it. If AdGuard is up but nothing resolves,
check that `upstreams_proxied` are **IP literals**: a hostname there can't be
resolved without DNS, which is the thing you're trying to fix.

## A client bypasses the tunnel

- IPv6. Check `ip -6 addr show` on the *client*. If it has a global v6 address,
  the router is still sending RAs — turn IPv6 off on the router.
- The client is using its own DoH/DoT (browsers do this by default). It still
  goes through the tunnel, but AdGuard won't see or filter it.
- The client's gateway isn't actually the box. Check its routing table.

## Nothing came back after a reboot

```bash
sudo gw check          # the "boot" section reports exactly which unit is not enabled
systemctl status gateway.target
journalctl -b -u gw-network -u xray
```

Usually one unit was never enabled — `sudo gw enable` fixes that. If the units
are enabled but the tunnel failed at boot and recovered a minute later, the
clock was wrong when Xray started: check that `chrony-wait.service` is enabled
(`systemctl is-enabled chrony-wait`), and consider replacing the CMOS battery.

If `gw-network` failed at boot, the firewall never loaded — meaning no
interception *and* no kill switch. `journalctl -b -u gw-network` shows the nft
error; it is almost always a ruleset referring to something that doesn't exist
yet, such as the `xray` user.

## Tailscale can't connect

If `route_control_via_xray = true`, tailscaled reaches the coordination server
through the tunnel — so a down tunnel takes Tailscale with it. That's what the
lifeline is for; `gw status` shows whether it engaged. To decouple them
permanently, set `route_control_via_xray = false` and `gw apply`.

If the lifeline engaged but didn't help, the cgroup rule may not have applied:

```bash
nft list chain inet gateway lifeline
```

nftables resolves the cgroup path to an ID when the rule is added, and that ID
changes whenever tailscaled restarts — the watchdog re-applies it each cycle, so
a persistently empty chain means the rule is being rejected, not going stale.
