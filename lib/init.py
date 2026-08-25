"""`gw init` — build gateway.toml by interview.

Detects what it can from the running system and parses a vless:// share link so
the XHTTP parameters don't have to be transcribed by hand (which is where these
setups usually go wrong).
"""

from __future__ import annotations

import ipaddress
import pathlib
import json
import re
import subprocess
import sys
import urllib.parse


def sh(*args: str) -> str:
    try:
        return subprocess.run(args, capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


def detect() -> dict:
    """Best-effort read of the current network setup, used as defaults."""
    out = {"wan_if": "eth0", "router": "", "lan_cidr": "", "static_ip": "", "prefix": 24}
    route = sh("ip", "-4", "route", "show", "default")
    m = re.search(r"default via (\S+) dev (\S+)", route)
    if m:
        out["router"], out["wan_if"] = m.group(1), m.group(2)
    addr = sh("ip", "-4", "-o", "addr", "show", "dev", out["wan_if"])
    m = re.search(r"inet (\S+)/(\d+)", addr)
    if m:
        out["static_ip"] = m.group(1)
        out["prefix"] = int(m.group(2))
        out["lan_cidr"] = str(
            ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
        )
    return out


def outbound_json(s: dict) -> dict:
    """Turn parsed link fields into a complete Xray outbound object.

    From here on the gateway treats it as opaque — this function exists only so
    a share link is still a one-paste setup.
    """
    stream = {
        "network": "xhttp",
        "security": s["security"],
        "xhttpSettings": {
            "host": s["host"] or s["address"],
            "path": s["path"],
            "mode": s["mode"],
        },
    }
    if s["x_padding"]:
        stream["xhttpSettings"]["xPaddingBytes"] = s["x_padding"]
    if s["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": s["sni"] or s["address"],
            "fingerprint": s["fingerprint"],
            "alpn": s["alpn"],
            "allowInsecure": False,
        }
    elif s["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": s["sni"] or s["address"],
            "fingerprint": s["fingerprint"],
            "publicKey": s["public_key"],
            "shortId": s["short_id"],
            "spiderX": s["spider_x"],
        }
    return {
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": s["address"],
                    "port": s["port"],
                    "users": [{"id": s["uuid"], "encryption": s["encryption"]}],
                }
            ]
        },
        "streamSettings": stream,
    }


def parse_vless(link: str) -> dict:
    """vless://uuid@host:port?type=xhttp&path=..&host=..&security=tls&sni=..#tag"""
    if not link.startswith("vless://"):
        raise ValueError("that is not a vless:// link")
    u = urllib.parse.urlparse(link)
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}

    if q.get("type", "xhttp") not in ("xhttp", "splithttp"):
        raise ValueError(
            f"transport is {q.get('type')!r}, but this gateway is built for xhttp. "
            "Use an XHTTP link, or edit gateway.toml by hand afterwards."
        )

    alpn = [a for a in q.get("alpn", "h2,http/1.1").split(",") if a]
    return {
        "address": u.hostname or "",
        "port": u.port or 443,
        "uuid": urllib.parse.unquote(u.username or ""),
        "encryption": q.get("encryption", "none"),
        "path": urllib.parse.unquote(q.get("path", "/")),
        "host": q.get("host", ""),
        "mode": q.get("mode", "auto"),
        "x_padding": q.get("xPaddingBytes", ""),
        "security": q.get("security", "tls"),
        "sni": q.get("sni", q.get("peer", "")),
        "fingerprint": q.get("fp", "chrome"),
        "alpn": alpn,
        "public_key": q.get("pbk", ""),
        "short_id": q.get("sid", ""),
        "spider_x": q.get("spx", "/"),
    }


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or default


def toml_str(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(f'"{x}"' for x in v) + "]"
    return '"' + str(v).replace('"', '\\"') + '"'


def main(repo: str, config: str) -> int:
    cfg_path = pathlib.Path(config)
    if cfg_path.exists():
        if ask(f"{cfg_path} exists. Overwrite? (yes/no)", "no") != "yes":
            print("keeping the existing config")
            return 0

    d = detect()
    print("\n-- network --")
    print("Detected from the running system; correct anything that's wrong.\n")
    wan_if = ask("interface facing the router", d["wan_if"])
    lan = ask("LAN CIDR", d["lan_cidr"] or "192.168.1.0/24")
    router = ask("router IP", d["router"] or "192.168.1.1")
    static_ip = ask(
        "static IP for this box (must be OUTSIDE the router's DHCP pool)",
        d["static_ip"],
    )
    prefix = ipaddress.ip_network(lan, strict=False).prefixlen

    print("\n-- xray --")
    print("Paste the vless:// XHTTP link from your server.\n")
    server = None
    while server is None:
        link = ask("vless:// link").strip()
        try:
            server = parse_vless(link)
        except ValueError as e:
            print(f"  {e}")
    print(f"  parsed: {server['address']}:{server['port']} path={server['path']} "
          f"mode={server['mode']} security={server['security']}")
    resolved = ask(
        "pin the server's IP? (removes the boot-time DNS dependency; blank to skip)",
        "",
    )

    print("\n-- misc --")
    tz = ask("timezone", "Asia/Tehran")

    # The outbound is written as its own JSON file; gateway.toml only points
    # at it. Everything downstream treats that file as opaque.
    ob_dir = pathlib.Path(repo, "outbounds")
    ob_dir.mkdir(exist_ok=True)
    ob_path = ob_dir / "main.json"
    if ob_path.exists() and ask(f"{ob_path} exists. Overwrite?", "yes") != "yes":
        print(f"keeping {ob_path}")
    else:
        ob_path.write_text(json.dumps(outbound_json(server), indent=2) + "\n")
        ob_path.chmod(0o600)
        print(f"\nwrote {ob_path} (0600 — it holds your credentials)")

    template = pathlib.Path(repo, "gateway.example.toml").read_text()
    subs = {
        r'wan_if     = "eth0"': f"wan_if     = {toml_str(wan_if)}",
        r'lan_cidr   = "192.168.1.0/24"': f"lan_cidr   = {toml_str(lan)}",
        r'router     = "192.168.1.1"': f"router     = {toml_str(router)}",
        r'static_ip  = "192.168.1.2"': f"static_ip  = {toml_str(static_ip)}",
        r"prefix_len = 24": f"prefix_len = {prefix}",
        r'timezone         = "Asia/Tehran"': f"timezone         = {toml_str(tz)}",
        r'server_ip = ""': f"server_ip = {toml_str(resolved)}",
    }
    for old, new in subs.items():
        if old not in template:
            print(f"warning: template line not found, skipping: {old}", file=sys.stderr)
            continue
        template = template.replace(old, new, 1)

    # The example ships two illustrative clients; they are almost certainly not
    # this LAN's devices.
    template = re.sub(
        r'\[\[client\]\]\nip     = "192\.168\.1\.\d+"\nname   = "[^"]+"\npolicy = "[\w-]+"\n\n?',
        "",
        template,
    )

    cfg_path.write_text(template)
    print(f"\nwrote {cfg_path}")
    print("Next:")
    print("  gw client add <ip> <name> proxy   # for each device that opts in")
    print("  sudo scripts/00-bootstrap.sh")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
