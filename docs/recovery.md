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

## You need the LAN working *now*

```bash
sudo gw panic
```

Tears down interception and leaves plain NAT. Every client keeps working,
**unproxied and with your real IP exposed** — it's a debugging mode, not a
fallback. `sudo gw apply` restores normal operation.

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
