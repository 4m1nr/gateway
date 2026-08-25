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

## The firewall loads, then disappears

`gw apply` reports `firewall loaded`, and moments later `gw status` says
`firewall not loaded` — while `gw-network` still shows `active`.

That combination is the tell. `gw-network` is `Type=oneshot` with
`RemainAfterExit=yes`, so it reports active once its rules are in place and
keeps reporting active even if something else removes them afterwards.

Almost always this is Debian's own `nftables.service`, which loads
`/etc/nftables.conf` — a file that begins with `flush ruleset` and therefore
erases every table, including this one. Two units cannot both own the ruleset.

```bash
systemctl is-enabled nftables.service    # expect: masked
sudo gw apply                            # masks it, with a warning
```

`gw check` fails if it is ever re-enabled.

To watch it happen, or to rule this out and look elsewhere:

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

**Apply fails from the dashboard but `gw apply` works in a shell.** The
dashboard runs `gw apply` as root through the helper, so the difference is
almost always a validation error surfaced in the returned output. Check
`journalctl -u gw-web -n 50`.

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
