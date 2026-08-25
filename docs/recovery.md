# Recovery

The gateway is a single point of failure for every device that opted in. This
is how you get out of trouble, roughly in order of how much access you still
have.

## A device lost internet, the box is otherwise fine

Point that device's default gateway back at the router. That's the whole
recovery — nothing on the box needs to change, and the device is immediately
back to normal (unproxied) internet.

This is the reason for the opt-in-per-device design: the blast radius of any
gateway problem is exactly the set of devices you configured.

## The tunnel is down, everything else works

Expected behaviour: proxied clients have **no internet at all**. That is the
kill switch working, not an extra failure. `direct` clients are unaffected.

```bash
gw status          # tunnel state + consecutive failure count
gw logs            # xray, firewall, health, adguard in one stream
sudo gw check      # find out which stage is actually broken
```

The watchdog restarts Xray after `restart_after_fails` probes on its own. If it
has been down past `lifeline_after_min`, tailscaled is released to a direct path
so you can still SSH in — `gw status` says `lifeline ENGAGED` when that happens.

## The box itself has no internet

This is the fail-closed design pointed at the gateway. Once
`gw-network.service` is loaded, the OUTPUT chain marks the box's own traffic
and policy-routes it to Xray — so if the tunnel is not carrying traffic, the
box has no internet either. Only NTP and the bypass list get out. If AdGuard is
also installed, `/etc/resolv.conf` points at it and its upstream DoH rides the
same dead tunnel, so DNS goes with it.

```bash
sudo gw panic          # routing direct again, and DNS falls back to the router
```

Then work out which layer is broken:

```bash
gw status                                    # is the tunnel up?
runuser -u xray -- curl -sS --max-time 10 https://api.ipify.org   # direct path
curl -sS --max-time 15 --socks5-hostname 127.0.0.1:10808 https://api.ipify.org
journalctl -u xray -n 40
```

`runuser -u xray` is the useful one: that uid is exempt from the OUTPUT chain,
so it tests the box's real connectivity regardless of the tunnel. If it works
and the SOCKS probe doesn't, the network is fine and Xray is the problem —
check the clock first, then the outbound JSON against the server.

## You need the LAN working *now*

```bash
sudo gw panic
```

Tears down interception and leaves plain NAT. Every client keeps working,
**unproxied and with your real IP exposed** — it's a debugging mode, not a
fallback. It also repoints `/etc/resolv.conf` at the router if local resolution
is dead, keeping the old file at `/etc/resolv.conf.gw-bak`; `sudo gw apply`
puts it back once AdGuard answers again.

## You can't reach the box at all

You need console access — monitor and keyboard on the thin client.

```bash
sudo gw panic                       # LAN back online, unproxied
sudo systemctl stop gw-network      # or remove interception entirely
sudo nft delete table inet gateway
```

If the box won't boot far enough for that, unplug it and point the affected
devices' gateways back at the router.

## A bad `gw apply`

`gw apply` validates before it reloads, so a broken ruleset or Xray config is
refused rather than applied. If something got through anyway:

```bash
cd /opt/gateway
git diff                    # what changed
git checkout gateway.toml   # or edit it back
sudo gw apply
```

AdGuard's config is backed up on every merge to
`/opt/AdGuardHome/AdGuardHome.yaml.bak`.

## Locked out of the dashboard

The lockout is in memory, so restarting the service clears it:

```bash
sudo systemctl restart gw-web     # clears lockouts and all sessions
sudo gw web-passwd                # or set a new password
```

The dashboard is a convenience. Everything it does is available from the shell
(`gw status`, `gw client`, `gw apply`), so losing access to it never blocks
recovery. If you want it gone entirely, set `enabled = false` under `[web]` and
run `sudo gw apply` — that removes the unit, the sudo grant and the firewall
rule together.

## Stopping or restarting the stack

```bash
sudo gw restart     # restart everything (tailscaled is left alone on purpose)
sudo gw disable     # stop it and remove it from boot — asks first
sudo gw enable      # put it back
```

`gw disable` stops the firewall as well as the tunnel, so proxied clients lose
connectivity entirely. If you want the LAN working while you investigate, use
`gw panic` instead.

## Undoing the whole thing

```bash
sudo gw panic
sudo systemctl disable --now gateway.target
sudo systemctl disable --now xray gw-network gw-health.timer gw-geoupdate.timer
sudo systemctl disable --now AdGuardHome tailscaled
sudo nft delete table ip gwpanic
sudo rm /etc/sysctl.d/99-gateway.conf /etc/systemd/network/10-gateway-wan.network
sudo systemctl restart systemd-networkd
```

Then set each opted-in device's gateway back to the router.
