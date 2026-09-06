# Moving a running gateway from one card to two

This converts a box that is already serving the LAN. It is not a fresh install,
and the difference matters: there are devices depending on this box right now,
and at least one step drops them.

Read the whole thing before starting. The short version:

- **Do it at the console.** Not over SSH from the LAN, and not over the address
  you are about to change.
- **The uplink segment never has to move.** The recommended path leaves the
  router untouched on the network it already serves, so the box keeps its own
  internet — and your tailnet access — whichever card you point at it.
- **The office LAN gets a new subnet**, and something on it has to serve DHCP.
  This box does not. Sorting that out is the part that takes planning; the
  gateway change itself is four lines of config.
- **Which card faces which way is your choice**, and it is only a choice about
  which name goes on which config line. There is one argument for a preference
  and it is in [Two decisions](#two-decisions-and-they-are-independent).

## What actually changes

One-armed, the box is a peer on the LAN and devices opt in by pointing at it.
Two-armed, it is the LAN's gateway, and there is no opting in: `[policy].default`
governs every device on that segment. Read yours before you start —

```bash
sed -n '/^\[policy\]/,/^\[/p' /opt/gateway/gateway.toml
```

— because the same value means something much broader on the far side of this
change. `direct` converts quietly: the wiring changes and nobody's traffic
does. `proxy` puts the entire office in the tunnel the moment a cable moves,
including whatever printer or till or badge reader nobody thought about. That
is usually the goal, but it should be a decision rather than a discovery, and
the safe order is to convert on `direct` and flip the one line afterwards.

## Two decisions, and they are independent

### 1. Which card faces the internet

Purely a naming choice in the config — `wan_if` is the card facing the router,
`lan_if` the one facing the office, and nothing else in the gateway cares which
of them is the built-in NIC. Put the new card on either side.

It is not quite free of consequence, though, and the consequence runs the
opposite way to intuition. Both cards carry the same volume: traffic comes in
one and goes out the other, so there is no "fast side" to give the better NIC
to. What differs is what breaks when a card does.

The uplink is the box's lifeline. Everything rides it — the tunnel, the
tailnet, your remote access. If the uplink card drops, the box is stranded and
you are driving over. If the LAN card drops, the office is offline but the box
is still reachable and still diagnosable from anywhere.

So if the new card is **USB**, there is a real argument for putting it on the
LAN side: USB adapters reset, and power management drops them, in a way a
soldered NIC does not. If it is **PCIe or M.2**, that argument mostly
evaporates and you should wire whichever way suits the room.

### 2. Which subnet gets renumbered

The office and the uplink cannot share a network — the validator refuses a
config where they overlap, because the kernel would have two routes for the
same space and the firewall no way to tell the sides apart. Since both are
`192.168.1.0/24` today, one of them has to move. This is a separate question
from which card goes where, and either answer works with either wiring.

**A. Renumber the LAN — recommended**

```
   router 192.168.1.1                       unchanged, DHCP left on
        │
   wan  │ 192.168.1.2      the uplink now, or just wan_dhcp = true
   ┌─────────────┐
   │  gateway    │
   └─────────────┘
   lan  │ 192.168.10.1     a NEW subnet
        │
      switch ── the office lives here
```

The router is not reconfigured at all. If the uplink takes a lease from it
(`wan_dhcp = true`) there is nothing to set on either side of that link.

The cost is that the office is renumbered and needs its own DHCP server.

**B. Renumber the uplink — only if you cannot renumber devices**

Keep the office on `192.168.1.0/24` and move the *router* to a new segment
(`10.0.0.0/24`, say). No device changes address, but the router has to be
reconfigured. Use this when touching every desk is impossible and touching the
router is not.

Either way the office loses its DHCP server, because that server is the router
and the router ends up on the far side of the box. See
[Moving the office across](#moving-the-office-across).

The rest of this document follows **A**, with the new card as the uplink. For
B, `lan_cidr` keeps its current value, `static_ip` becomes the address devices
are already pointed at, and `wan_ip`/`router` describe the new upstream segment.

## Getting the second card

A thin client has one NIC, so this is a purchase before it is a procedure.

**USB 3.0, not USB 2.0.** A 2.0 adapter tops out at 480 Mb/s shared with the
bus and will be slower than the single-NIC hairpin you are removing — the
change would cost throughput rather than gain it. Check the port too: on most
HP thin clients only some of them are 3.0 (blue, or marked SS).

**Chipset matters more than brand.** Debian ships in-tree drivers for the two
that are worth buying, so neither needs anything installed:

| Chipset | Driver | Notes |
| --- | --- | --- |
| Realtek RTL8153 | `r8152` | the common one, and fine |
| ASIX AX88179 / AX88179A | `ax88179_178a` | equally fine |

Avoid anything that ships a driver on a mini-CD. On a box with no working
internet, a NIC that needs a download to work is a NIC that does not work.

If the machine has a free PCIe or M.2 slot, an internal card is better than
USB — no bus contention, and nothing to knock out of a socket. Worth opening
the case to check before ordering.

When it arrives, plug it in with the box running and confirm the kernel took
it before changing any config:

```bash
sudo dmesg -w        # watch while you plug it in
ip -br link          # the new name should appear
ethtool <name> | grep -i speed
```

## Before you start

Find the second card and confirm the kernel sees it:

```bash
ip -br link
```

A USB gigabit adapter usually appears as `enx` plus its MAC, a PCIe one as
`enp*`. Write the name down — it goes in the config verbatim, and a typo here
is a box whose LAN side comes up on nothing. Plug it into the new switch now,
before any config changes: an interface with no address on a live segment does
nothing at all.

Then record what you are changing away from, so a rollback is a paste rather
than a memory:

```bash
grep -A8 '^\[net\]' /opt/gateway/gateway.toml
ip -br addr
ip route show default
```

Arm the deadman while you work. If the box strands itself, this puts it back
without a drive:

```bash
sudo scripts/deadman.sh arm 20m    # rolls the gateway back in 20 minutes
# ... and when you are done and it all works:
sudo scripts/deadman.sh disarm
```

## The config change

Edit `gateway.toml`. Nothing else in the file changes.

```toml
[net]
wan_if     = "enx00e04c680001"   # NEW card, plugged into the router
lan_if     = "eth0"              # the built-in NIC, facing the office
lan_cidr   = "192.168.10.0/24"   # NEW subnet for the office
static_ip  = "192.168.10.1"      # this box, now the LAN's gateway
prefix_len = 24

# The uplink sits on the segment the router already serves, so let the router
# hand it an address and there is nothing to keep in step:
wan_dhcp   = true

# Or pin it, if you would rather the box's uplink address never move. Then
# router must be inside this network rather than inside lan_cidr:
# wan_ip          = "192.168.1.2"   # what static_ip used to be
# wan_prefix_len  = 24
# router          = "192.168.1.1"   # unchanged
```

Note which name is on which line. Swapping `wan_if` and `lan_if` produces a
config that validates perfectly and a box that serves the office out of the
router's port — everything unreachable, nothing saying why.

Two things move meaning here and it is worth saying them out loud. `static_ip`
was the box's address on the shared segment; it is now the LAN's gateway.
`router` was inside `lan_cidr`; it is now on the uplink, and the validator
refuses the config if you leave it on the LAN side. Naming a router *and*
setting `wan_dhcp` is rejected too, rather than one of them being ignored.

Any `[[client]]` entries are keyed to addresses on the old subnet and will be
rejected as outside `lan_cidr`. Update them to the new addresses, or remove
them and re-add once devices have moved.

Check it before it touches anything:

```bash
gw render          # fails here if the config is wrong. Nothing is installed.
sudo gw diff       # exactly what would change on the box
```

`gw diff` should show the new `15-gateway-lan.network`, a rewritten
`10-gateway-wan.network`, an nftables ruleset with a `LAN_IF` define and a
`wan-spoofed-lan` rule, and sysctl entries for both cards. If it shows anything
about the uplink's address changing, you have mistyped `wan_ip`.

## Applying it

**At the console.** This reconfigures both cards.

```bash
sudo gw apply
```

Apply now reconfigures the links it rewrote and removes any address the config
no longer names — that is what stops the card ending up on the old address and
the new one at once. It reports each address it drops. If it says it could not
reconfigure the links, check `ip -br addr` before going further.

Then:

```bash
ip -br addr           # eth0 on the uplink, the new card on 192.168.10.1
ping -c2 192.168.1.1  # the router, over the uplink
sudo gw check         # the LAN card is checked explicitly now
```

At this point the box is a two-armed gateway with nothing behind it. The old
segment still works, because it is still wired the way it was.

## Moving the office across

DHCP first, devices second — and on a **new** subnet, "first" is doing real
work: there is nothing on that segment yet, so nothing is handing out anything.
Nominate the server before you move a single device, or the first machine you
replug simply has no address.

Whatever will serve the new segment — a Wi-Fi AP with a DHCP server, a managed
switch, a small always-on machine, or the old router demoted to AP duty *on the
LAN side* — must hand out:

- **gateway:** `192.168.10.1` (this box)
- **DNS:** `192.168.10.1` (this box, again)

Both, and this is not belt-and-braces. A device that keeps resolving somewhere
else gets a private address for a blocked name, sends real traffic to it, and
the gateway drops it as unreachable. The symptom is one site failing while
everything else works, and it is a miserable thing to chase.

If it turns out nothing on the new segment can serve DHCP, the box itself can:
AdGuard Home is already running here and has a DHCP server built in. It is off,
and the gateway does not configure it — turning it on is a decision to make in
AdGuard's own UI, and it then owns leases for that segment. Reach for it only
when the alternative is static addresses on every desk.

Then move devices to the new switch. Each one that lands there is behind the
tunnel immediately — no per-device step, which is the whole point of the
change. Confirm with the first one before moving the rest:

```bash
sudo gw diag 192.168.10.50      # what the kernel does with that client's packets
```

## Verifying

```bash
sudo gw check
```

New in the two-armed shape: the LAN card exists, is up, and carries exactly
`static_ip` and nothing else; and under `wan_dhcp`, that a lease actually
arrived. `gw bench` also stops blaming the single-NIC hairpin, because there
isn't one any more — traffic comes in one card and leaves the other, and the
old 50%-of-link ceiling is gone.

Once you are satisfied:

```bash
sudo scripts/deadman.sh disarm
```

## Rolling back

If it is going badly and you have console access, the fastest way back is the
config. Put `[net]` back exactly as you recorded it at the start — and check
`wan_if` in particular, because it is the line most easily left wrong. In the
two-armed config it names the new card; one-armed it has to name the built-in
NIC again, since that is the one the office is plugged into. Removing `lan_if`
and leaving `wan_if` pointing at the new card gives you a one-armed gateway
serving the office out of the wrong port: a valid config, and a dead box.

Then `sudo gw apply`. It removes the two-armed `.network` unit, puts the single
card back on its old address, and strips the addresses the config no longer
names. Move the office cable back to the router's switch and it is as it was.

If you have lost access to the box entirely, the deadman does it unattended —
which is why it is armed at the top of this document. See
[recovery.md](recovery.md).
