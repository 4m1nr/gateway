"""Regenerate every fixture from gateway.example.toml.

Fixtures are derived, not hand-maintained: when the example config changes, a
stale fixture silently stops exercising the thing it was written for (a
`.replace()` that no longer matches leaves the default in place, and the test
still passes). Run this after editing the example.
"""

import pathlib
import re
import sys

BASE = pathlib.Path("gateway.example.toml").read_text()
OUT = pathlib.Path("tests/fixtures")


def write(name: str, text: str, must_differ: bool = True) -> None:
    if must_differ and text == BASE:
        sys.exit(f"fixture {name} is identical to the example — a replace() missed")
    (OUT / f"{name}.toml").write_text(text)


def sub(text: str, old: str, new: str, name: str) -> str:
    if old not in text:
        sys.exit(f"{name}: pattern not found in the example config:\n  {old!r}")
    return text.replace(old, new)


write("default", BASE, must_differ=False)

t = sub(BASE, 'mode = "off"', 'mode = "pass"', "ipv6-pass")
t = re.sub(r'\[\[client\]\]\nip     = "192\.168\.1\.(60|99)"\nname   = "[^"]+"\npolicy = "[\w-]+"\n\n?', '', t)
t = sub(t, "route_control_via_xray = true", "route_control_via_xray = false", "ipv6-pass")
write("ipv6-pass-no-clients", t)

t = sub(BASE, 'file = "outbounds/main.json"', 'file = "outbounds/reality.json"', "reality")
t = sub(t, "block_bittorrent = false", "block_bittorrent = true", "reality")
t = sub(t, "block_geosite  = []", 'block_geosite  = ["geosite:category-ads-all"]', "reality")
t = sub(t, '''[xray.fallback]
enabled = false
# file      = "outbounds/backup.json"
# server_ip = ""''', '''[xray.fallback]
enabled = true
file    = "outbounds/backup.json"''', "reality")
write("reality-fallback", t)

t = sub(BASE, "enabled        = true", "enabled        = false", "no-tailscale")
t = sub(t, 'server_ip = ""', 'server_ip = "203.0.113.10"', "no-tailscale")
write("no-tailscale", t)

for pol in ("direct", "block"):
    t = re.sub(r'^default = "proxy"$', f'default = "{pol}"', BASE, flags=re.M)
    if t == BASE:
        sys.exit("default-policy fixture: policy.default line not found")
    write(f"default-policy-{pol}", t)

t = re.sub(r"^enabled = true$", "enabled = false", BASE, count=1, flags=re.M)
write("no-web", t)

write("trojan-upstream",
      sub(BASE, 'file = "outbounds/main.json"', 'file = "outbounds/trojan.json"', "trojan"))

t = sub(BASE, 'socks_proxy = ""', 'socks_proxy = "socks5h://127.0.0.1:1080"', "proxy")
t = sub(t, 'repo = "Chocolate4U/Iran-v2ray-rules"', 'repo = ""', "proxy")
t = sub(t, "files = []", 'files = ["geoip", "geosite"]', "proxy")
t = sub(t, 'url_template = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/{0}.dat"',
        'url_template = "https://mirror.example.com/v2ray/{0}.dat"', "proxy")
write("bootstrap-proxy", t)

PROFILES = BASE + '''
[[upstream]]
name = "work"
file = "outbounds/work.json"

[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via     = "work"
  domains = ["domain:corp.work-example.com"]
  ips     = ["10.20.0.0/16", "203.0.113.0/24"]

  [[profile.route]]
  via     = "block"
  domains = ["geosite:category-ads-all"]

[[profile]]
name = "mostly-local"
base = "direct"

  [[profile.route]]
  via = "work"
  ips = ["10.20.0.0/16"]

  [[profile.route]]
  via     = "proxy"
  domains = ["domain:news.example.com"]

[[client]]
ip     = "192.168.1.70"
name   = "work-laptop"
policy = "work-laptop"

[[client]]
ip     = "192.168.1.71"
name   = "desktop"
policy = "mostly-local"
'''
write("profiles", PROFILES)

write("exit-node-profile",
      sub(PROFILES, 'exit_node_policy = "proxy"', 'exit_node_policy = "work-laptop"', "exit-profile"))
write("exit-node-direct",
      sub(PROFILES, 'exit_node_policy = "proxy"', 'exit_node_policy = "direct"', "exit-direct"))

write("custom-routes", PROFILES + '''
[[route]]
position    = "first"
ip          = ["203.0.113.5/32"]
port        = "22"
outboundTag = "block"

[[route]]
domain      = ["domain:intranet.example.com"]
outboundTag = "direct"

[[route]]
ip          = ["198.51.100.0/24"]
outboundTag = "work"

[[route]]
position    = "after"
port        = "5353"
network     = "udp"
outboundTag = "direct"

[[route]]
position = "first"
json     = """
{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }
"""
''')


# Scheduled jobs. Built with a placeholder for the TOML literal-string quote so
# this file does not have to nest triple quotes, and so the bash below (which
# contains %, $() and backslash continuations) survives verbatim — the exact
# characters that naive storage mangles.
Q = chr(39) * 3
JOBS = """
[[job]]
name        = "backup-config"
description = "Copy the AdGuard config somewhere safe"
schedule    = "0 4 * * *"
script      = @Q@
install -d /var/backups/gateway
cp -a /opt/AdGuardHome/AdGuardHome.yaml \\
      /var/backups/gateway/AdGuardHome-$(date +%F).yaml
find /var/backups/gateway -name 'AdGuardHome-*.yaml' -mtime +14 -delete
@Q@

[[job]]
name        = "speedtest"
description = "Log throughput through the tunnel"
schedule    = "@hourly"
user        = "nobody"
script      = @Q@
curl -o /dev/null -s -w 'down %{speed_download} B/s\\n' \\
     --socks5-hostname 127.0.0.1:10808 \\
     https://speed.cloudflare.com/__down?bytes=10000000
@Q@

[[job]]
name     = "parked"
schedule = "@weekly"
enabled  = false
script   = "echo this one is disabled"
""".replace("@Q@", Q)
write("jobs", BASE + JOBS)

print(f"regenerated {len(list(OUT.glob('*.toml')))} fixtures")
