# Troubleshooting

Start with `sudo gw check` — it isolates which stage is broken. What follows is
symptom → cause, ordered by how often each one is actually the problem.

## The tunnel won't come up at all

**Check the clock first.** `date -u`, then `chronyc tracking`. TLS and REALITY
both fail on skew and the symptom looks exactly like a broken tunnel or wrong
credentials. NTP is pinned to a direct path precisely so this is fixable
without the tunnel.

Then the outbound itself. `outbounds/main.json` is passed to Xray verbatim, so
compare it against what the server expects — for XHTTP that means `path`,
`host`, `mode`, `alpn` and `serverName`.

`journalctl -u xray -n 50` shows the handshake failure. A CDN or reverse proxy
in front of the server that doesn't pass the path through unchanged is a common
cause; so is `h2` in `alpn` when the front only speaks HTTP/1.1.

Because the outbound is plain Xray JSON, you can test it in isolation: copy it
into a minimal config with a SOCKS inbound and run
`xray run -c /tmp/test.json` by hand. If it fails there too, the problem is the
outbound, not the gateway.

**"sockopt.mark is N, but the firewall exempts 255".** Your outbound sets its
own mark. The gateway needs that exact value to recognise Xray's own packets and
keep them out of TPROXY; a different one deadlocks the box. Remove the field —
the gateway adds it — or change `xray.outbound_mark` to match.

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

## The box has no internet but LAN clients do

And `gw status` says the tunnel is up. The giveaway is in the Xray log:

```bash
journalctl -u xray -n 40 --no-pager -o cat | grep accepted
```

If every line says `[socks-in -> proxy]` and none says `tproxy-in`, the box's
own traffic is not reaching Xray at all. The health probe uses the SOCKS
inbound directly, so it goes on reporting the tunnel up while nothing else
works — the one check meant to catch this cannot see it.

Local traffic takes a longer path than forwarded traffic: the output chain
marks it, `ip route local default dev lo` in table 100 loops it back in through
`lo`, and it is intercepted in **prerouting**, the only hook where `tproxy` is
valid. A prerouting chain that returns early on `iif lo` skips exactly those
packets, which are then routed to a local address nothing is listening on and
silently disappear.

```bash
nft list chain inet gateway prerouting | head
```

The `iif lo meta mark 0x1 ... tproxy` rule must come **before** `iif lo return`.
`tests/run.sh` asserts that ordering.

## A proxied client has no internet

That is the kill switch, and it means Xray isn't listening:

```bash
gw status
ss -lnt sport = :12345
nft list chain inet gateway forward | grep killswitch   # drop counter climbing
```

Fix the tunnel; the client recovers on its own.

## Clients get about half the speed of the proxy on the device

Measure before tuning:

```bash
sudo gw bench
```

It reports the NIC link speed and duplex, whether the CPU has AES
acceleration, and throughput *through* the tunnel against throughput
*bypassing* it — which is what separates "Xray is slow" from "the LAN is slow"
from "your upstream is slow".

**The usual answer is the single NIC.** Xray terminates the client's
connection and opens its own, so every byte crosses the interface twice: in
from the client, out to the internet. A 100 Mb/s link therefore caps clients
near 50 Mb/s no matter how fast the tunnel is — an exact halving, which is why
it reads as a proxy problem. `gw bench` says so explicitly when it sees a
100 Mb/s link.

The fix is a second NIC (a USB 3.0 gigabit adapter): one leg in, one leg out,
and the ceiling disappears. Nothing in the config can work around it.

Other causes, in the order `gw bench` will point at them:

- **No AES-NI.** An older thin client does TLS in software, and that is
  usually the ceiling. `grep -m1 ' aes ' /proc/cpuinfo` — if it is absent,
  the CPU is the limit.
- **Half duplex** on the link. Almost always a bad cable or a forced port
  speed. Collisions destroy throughput far out of proportion.
- **The tunnel itself** — if `gw bench` shows the tunnel well under direct,
  the server or the path to it is the constraint, not this box.

`[performance]` in `gateway.toml` tunes the buffer size, congestion control
and Nagle. Those are worth adjusting once `gw bench` says the bottleneck is
actually the tunnel; they cannot help a saturated NIC.

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

## Clients get no reply, but the box itself works

The signature: `tcpdump` shows the client's SYNs arriving and nothing going
back, the prerouting counters say the traffic was intercepted, and
`input-intercepted` stays at zero.

```bash
sudo tcpdump -ni <wan-if> -c 20 host <client> and port 443   # In, never Out
sudo gw diag <client>                                        # intercepted > 0, input-intercepted 0
```

Packets counted by the tproxy rule but never reaching the input chain are
being dropped by the kernel in between — which happens when the tproxy target
is a loopback address. `tproxy ip to 127.0.0.1:PORT` rewrites the destination,
and a packet arriving on a real interface with a `127.0.0.0/8` destination is a
martian, dropped during the route lookup.

The box's own traffic is unaffected, because it is looped back through `lo`
where that destination is legitimate — so the gateway works and every client
fails.

```bash
nft list chain inet gateway prerouting | grep tproxy   # must be "to :PORT"
```

`tproxy ip to :PORT` keeps the original destination and changes only the port
for the socket lookup. `tests/run.sh` fails if a loopback target reappears.

To watch a specific client's packets move through the ruleset rule by rule:

```bash
sudo gw trace <client-ip>
```

## A client has no internet with the box as its gateway

Usually DNS. If the client still uses the router's resolver, blocked names
resolve to a private address, and the gateway drops traffic aimed there because
it is genuinely unreachable — the alternative, bypassing it, black-holes the
packets silently.

```bash
nft list chain inet gateway prerouting | grep -A1 poisoned-dns   # counter climbing?
```

A climbing `poisoned-dns` counter confirms it. Point the client's DNS at the
box, or set the router's DHCP to hand out the box as the DNS server.

If that counter is flat, check whether the client reaches Xray at all:

```bash
journalctl -u xray -f          # then load a page on the client
nft list chain inet gateway forward | grep -A1 killswitch
```

A climbing `killswitch` counter means the traffic reached the forward chain
instead of being intercepted. No log lines and no counters means the packets
are not arriving — check the client's default gateway, and that its address is
inside `net.lan_cidr`.

## A client's internet drops out now and then, and comes back

The hard part of this one is that every live command lies to you. By the time
you run `gw diag` the box is healthy — and it really is healthy, so a clean
report proves nothing and invites a guess. Read what was recorded instead:

```bash
sudo gw history 48 <client-ip>
```

It answers, in order:

1. **Did the health probe see an outage?** If it did, the timestamps line up
   with the client's and the fault is the tunnel — go read the Xray journal at
   that moment.
2. **Did Xray restart?** A restart drops every live connection on every client.
   The client notices immediately; the probe, thirty seconds later, sees a
   healthy tunnel and reports nothing wrong. So "no outage logged, but xray
   restarted" means *the restart was the outage*.
3. **Did conntrack fill, or did the OOM killer run?** Both drop new connections
   while leaving established ones alone, which on a phone looks exactly like
   the internet coming and going. A gateway holds far more flows than a
   workstation, and a phone on QUIC opens a lot of them; the health probe warns
   at 80% so you see it coming.
4. **Was the client still asking this box for DNS?** The per-hour histogram
   comes from AdGuard's own query log. An hour marked `<- silence` means the
   client stopped asking — it left the wifi, or fell back to another resolver.
   Steady queries through the outage means DNS was fine and the data path was
   not.

Two things that look like gateway faults and are not:

- **A phone roaming between APs, or its wifi sleeping.** The gap shows up in
  the DNS histogram and nowhere else on the box.
- **Android's connectivity check.** Android decides a network is "no internet"
  from its own probe to a Google endpoint. Over a high-latency tunnel that
  probe can time out while everything else works, and Android will then show
  the warning — and on some builds silently switch to mobile data.

## A client bypasses the tunnel

- IPv6. Check `ip -6 addr show` on the *client*. If it has a global v6 address,
  the router is still sending RAs — turn IPv6 off on the router.
- The client is using its own DoH/DoT (browsers do this by default). It still
  goes through the tunnel, but AdGuard won't see or filter it.
- The client's gateway isn't actually the box. Check its routing table.

## The firewall "disappears" between commands

`sudo gw apply` reports `firewall loaded`, then plain `gw status` says
`firewall not loaded` — with `gw-network` active throughout.

**Check PATH first.** `nft` lives in `/usr/sbin`, which is missing from some
root PATHs. `sudo` supplies its own `secure_path` (which includes `/usr/sbin`),
so anything run under sudo finds `nft` and anything run directly does not — and
the check then reads a missing binary as a missing firewall.

```bash
command -v nft || echo 'nft not on PATH — that is the bug, not the firewall'
```

`gw` now sets an explicit PATH and refuses to start if `nft` or `ip` is
missing, so this should not recur. `command not found` from any gw command is
the same root cause.

If `nft` is on PATH and the table really is being removed, the other cause is
Debian's own `nftables.service`: it loads `/etc/nftables.conf`, which begins
with `flush ruleset` and erases every table including this one. Two units
cannot both own the ruleset.

```bash
systemctl is-enabled nftables.service    # expect: masked
sudo gw apply                            # masks it, with a warning
```

`gw check` fails if it is ever re-enabled.

To watch the ruleset itself change, which settles it either way:

```bash
sudo nft monitor > /tmp/nftmon.log 2>&1 &
sudo gw apply
sleep 20; sudo kill %1
grep -E '^(add|delete|flush) table' /tmp/nftmon.log
```

Or poll it:

```bash
sudo systemctl restart gw-network
for i in $(seq 1 15); do
  nft list table inet gateway >/dev/null 2>&1 && s=loaded || s=GONE
  echo "$((i*2))s $s"; sleep 2
done
journalctl -n 60 --no-pager -o short-iso | grep -iE 'nft|gw-network'
```

If it survives 30 seconds there but vanishes later, something on a timer is
doing it — `nft list ruleset | grep '^table'` will show whose tables are
present.

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

## Downloads fail during setup

The box has no tunnel yet. If it also has no usable direct route, point the
setup jobs at a proxy:

```toml
[bootstrap]
socks_proxy = "socks5h://127.0.0.1:1080"
```

or `sudo gw --proxy socks5h://127.0.0.1:1080 update xray` for one command. This
covers Xray, AdGuard, geodata and apt. Clear it once the gateway works — the
box proxies its own traffic from then on.

## An Xray update went wrong

It shouldn't leave you stranded: the new binary is tested against the live
config before it is installed, and the old one is kept.

```bash
sudo gw update --check                       # what is installed vs available
ls -la /usr/local/bin/xray.previous          # the version you were on
sudo install -m755 /usr/local/bin/xray.previous /usr/local/bin/xray
sudo systemctl restart xray
```

"Xray vX rejects the current config" means a breaking change between versions,
not a gateway bug — the outbound JSON is passed through untouched. Check that
release's notes, adjust `outbounds/*.json`, then retry.

## The dashboard

**"Your address is not permitted" (403).** You are outside `web.allow_cidrs`.
It defaults to the LAN plus the tailnet. Note the packet also has to get past
the firewall first, so a 403 means you reached the service — if you get a
connection timeout instead, that is the nftables rule, not the app.

**Every login fails, even with the right password.** Either no password is set
(`sudo gw web-passwd`), or you are locked out — five failures per address
locks that address for 15 minutes, and a correct password during the lockout
is still refused. `journalctl -u gw-web` logs both cases.

**"Could not check the password" (500).** The sudo grant is broken. The web
process cannot verify anything on its own by design:

```bash
sudo -u gwweb sudo -n /usr/local/lib/gateway/web-action.py <<< '{"action":"auth_status"}'
sudo visudo -cf /etc/sudoers.d/gw-web
```

**Buttons do nothing / 403 on every change.** A CSRF token mismatch, usually
after `gw-web` restarted and invalidated sessions. Reload the page and sign in
again.

**Browser certificate warning.** Expected — the certificate is self-signed by
`scripts/40-web.sh`. Accept it once, or reach the dashboard over Tailscale.

**"could not reach the privileged helper".**

The dashboard cannot run its helper at all. `journalctl -u gw-web -n 30` now
logs the underlying reason for each attempt. Check the sudo grant directly:

```bash
sudo -u gwweb sudo -n /usr/bin/systemd-run --pipe --wait --collect --quiet \
  /usr/local/lib/gateway/web-action.py <<< '{"action":"auth_status"}'
sudo visudo -cf /etc/sudoers.d/gw-web
```

`gw-web.service` is deliberately sandboxed twice over — `ProtectSystem=strict`
makes the filesystem read-only, and `RestrictNamespaces=true` stops the process
escaping that by itself. Both apply to anything it starts with sudo, including
the helper. That is why the helper is launched through `systemd-run`: PID 1
runs it as a fresh transient unit, outside both restrictions, while the
network-facing process keeps them.

**"Read-only file system" from the dashboard.**

```
OSError: [Errno 30] Read-only file system: '/opt/gateway/gateway.toml'
```

`gw-web.service` runs with `ProtectSystem=strict`, and a process started with
sudo from inside a service **inherits that service's mount namespace** — so the
privileged helper is genuinely root and still sees a read-only `/opt` and
`/etc`. Being root is not enough; the filesystem view is the restriction.

The helper re-enters PID 1's mount namespace before touching anything, which
keeps the sandbox on the network-facing process where it belongs. If this
returns, check that `nsenter` exists (`util-linux`) and that the helper still
contains `escape_service_sandbox`.

**Apply fails from the dashboard but `gw apply` works in a shell.** The
dashboard runs `gw apply` as root through the helper, so the difference is
almost always a validation error surfaced in the returned output. Check
`journalctl -u gw-web -n 50`.

## Tailscale says "IP forwarding is disabled" but forwarding works

```
health: Subnet routing is enabled, but IP forwarding is disabled.
        Check that IP forwarding is enabled on your machine.
```

The message names IPv4 forwarding, which is almost never the one that is off.
Tailscale checks **both** families, and `--advertise-exit-node` advertises
`::/0` alongside `0.0.0.0/0` — there is no v4-only exit node — so IPv6
forwarding being off is enough on its own to produce this, on a box that is
forwarding IPv4 perfectly well.

With `[ipv6] mode = "off"` that used to be exactly the state: IPv6 disabled on
the LAN interface, and `net.ipv6.conf.all.forwarding` never set. `gw apply`
now sets it, so:

```bash
cd /opt/gateway && git pull && sudo gw apply
sudo gw check          # "IPv6 forwarding on", and no tailscale health warnings
```

Enabling it changes nothing on the LAN: the WAN interface has `disable_ipv6=1`
so no IPv6 exists there, and the ruleset drops IPv6 everywhere except from
`tailscale0`. It removes a disagreement rather than opening a path — the
firewall was already allowing tailnet IPv6 through the forward chain while the
kernel silently refused to forward it.

It does not give you an IPv6 exit node: the box has no IPv6 route to the
internet. A peer using it for IPv6 now gets an immediate unreachable and falls
back to IPv4, instead of its packets vanishing.

Read the values yourself with:

```bash
sudo gw diag            # the "forwarding" section shows both families
```

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
