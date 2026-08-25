"""Load, validate and normalise gateway.toml.

Stdlib only (tomllib is 3.11+; Debian 13 ships 3.13). No pip installs on the
box, which keeps `gw apply` usable on a broken-network gateway.
"""

from __future__ import annotations

import ipaddress
import pathlib
import sys
import tomllib

TAILNET_V4 = "100.64.0.0/10"

# Destinations that must never enter the tunnel: local scopes, the tailnet,
# and anything the kernel treats specially.
RESERVED_DST = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/4",
    "240.0.0.0/4",  # includes 255.255.255.255
    TAILNET_V4,
]

POLICIES = ("proxy", "direct", "block")


class ConfigError(Exception):
    pass


def _need(d: dict, key: str, where: str):
    if key not in d:
        raise ConfigError(f"[{where}] is missing required key '{key}'")
    return d[key]


def _ip(value: str, where: str) -> str:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise ConfigError(f"{where}: {value!r} is not a valid IP address")
    return value


def _net(value: str, where: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise ConfigError(f"{where}: {value!r} is not a valid CIDR")


class Config:
    """Validated config plus everything derived from it."""

    def __init__(self, raw: dict, path: pathlib.Path):
        self.raw = raw
        self.path = path

        net = _need(raw, "net", "root")
        self.wan_if = _need(net, "wan_if", "net")
        self.lan = _net(_need(net, "lan_cidr", "net"), "net.lan_cidr")
        self.lan_cidr = str(self.lan)
        self.router = _ip(_need(net, "router", "net"), "net.router")
        self.box_ip = _ip(_need(net, "static_ip", "net"), "net.static_ip")
        self.prefix_len = int(net.get("prefix_len", self.lan.prefixlen))

        for label, addr in (("router", self.router), ("static_ip", self.box_ip)):
            if ipaddress.ip_address(addr) not in self.lan:
                raise ConfigError(
                    f"net.{label} ({addr}) is not inside net.lan_cidr ({self.lan_cidr})"
                )
        if self.router == self.box_ip:
            raise ConfigError("net.router and net.static_ip cannot be the same address")

        self.ipv6_mode = raw.get("ipv6", {}).get("mode", "off")
        if self.ipv6_mode not in ("off", "pass"):
            raise ConfigError("ipv6.mode must be 'off' or 'pass'")

        # ---- xray -----------------------------------------------------------
        xr = _need(raw, "xray", "root")
        self.tproxy_port = int(xr.get("tproxy_port", 12345))
        self.socks_port = int(xr.get("socks_port", 10808))
        self.http_port = int(xr.get("http_port", 10809))
        # Loopback stats API. Makes "did this flow go direct or through the
        # tunnel?" answerable exactly, instead of by inference.
        self.api_port = int(xr.get("api_port", 10085))
        self.log_level = xr.get("log_level", "warning")
        self.domain_strategy = xr.get("domain_strategy", "IPIfNonMatch")
        self.outbound_mark = int(xr.get("outbound_mark", 255))
        self.server = self._server(_need(xr, "server", "xray"), "xray.server")
        fb = xr.get("fallback", {})
        self.fallback = self._server(fb, "xray.fallback") if fb.get("enabled") else None

        # ---- routing --------------------------------------------------------
        rt = raw.get("routing", {})
        self.direct_geosite = rt.get("direct_geosite", ["geosite:private"])
        self.direct_geoip = rt.get("direct_geoip", ["geoip:private"])
        self.block_geosite = rt.get("block_geosite", [])
        self.block_bittorrent = bool(rt.get("block_bittorrent", False))

        # ---- dns ------------------------------------------------------------
        dns = raw.get("dns", {})
        self.dns_port = int(dns.get("adguard_port", 53))
        self.ui_port = int(dns.get("adguard_ui_port", 3000))
        self.up_proxied = dns.get("upstreams_proxied", ["https://1.1.1.1/dns-query"])
        self.up_direct = dns.get("upstreams_direct", ["1.1.1.1"])
        self.direct_suffixes = dns.get("direct_suffixes", ["ir"])
        self.bootstrap = dns.get("bootstrap", ["1.1.1.1"])
        self.blocklists = dns.get("blocklists", [])
        self.querylog_days = int(dns.get("querylog_days", 3))
        self.statslog_days = int(dns.get("statslog_days", 7))

        for u in self.up_proxied:
            if u.startswith("https://"):
                hostpart = u[len("https://"):].split("/")[0].split(":")[0]
                try:
                    ipaddress.ip_address(hostpart)
                except ValueError:
                    raise ConfigError(
                        f"dns.upstreams_proxied: {u!r} uses a hostname. Use an IP "
                        "literal (https://1.1.1.1/dns-query) — a hostname here needs "
                        "DNS to resolve the DNS server, which cannot work at boot."
                    )

        # ---- clients --------------------------------------------------------
        self.default_policy = raw.get("default_policy", "proxy")
        if self.default_policy not in POLICIES:
            raise ConfigError(f"default_policy must be one of {POLICIES}")

        self.clients = []
        seen = set()
        for i, c in enumerate(raw.get("client", [])):
            where = f"client[{i}]"
            ip = _ip(_need(c, "ip", where), f"{where}.ip")
            pol = c.get("policy", self.default_policy)
            if pol not in POLICIES:
                raise ConfigError(f"{where}.policy must be one of {POLICIES}")
            if ip in seen:
                raise ConfigError(f"{where}: duplicate client ip {ip}")
            if ipaddress.ip_address(ip) not in self.lan:
                raise ConfigError(f"{where}: {ip} is not inside net.lan_cidr")
            if ip in (self.box_ip, self.router):
                raise ConfigError(f"{where}: {ip} is the gateway or the router itself")
            seen.add(ip)
            self.clients.append(
                {"ip": ip, "name": c.get("name", ip), "policy": pol}
            )

        # ---- tailscale ------------------------------------------------------
        ts = raw.get("tailscale", {})
        self.ts_enabled = bool(ts.get("enabled", True))
        self.ts_ssh = bool(ts.get("ssh", True))
        self.ts_exit_node = bool(ts.get("exit_node", True))
        self.ts_subnet_router = bool(ts.get("subnet_router", True))
        self.ts_proxy_egress = bool(ts.get("proxy_tailnet_egress", True))
        self.ts_route_control = bool(ts.get("route_control_via_xray", True))
        self.ts_lifeline_min = int(ts.get("lifeline_after_min", 10))

        # ---- health ---------------------------------------------------------
        h = raw.get("health", {})
        self.health_interval = int(h.get("interval_sec", 30))
        self.probe_url = h.get("probe_url", "https://www.gstatic.com/generate_204")
        self.probe_timeout = int(h.get("probe_timeout_sec", 8))
        self.domestic_probe_url = h.get("domestic_probe_url", "https://www.irna.ir")
        self.restart_after = int(h.get("restart_after_fails", 3))
        self.fallback_after = int(h.get("fallback_after_fails", 6))
        if self.fallback_after < self.restart_after:
            raise ConfigError(
                "health.fallback_after_fails must be >= health.restart_after_fails"
            )

        # ---- system ---------------------------------------------------------
        sy = raw.get("system", {})
        self.timezone = sy.get("timezone", "UTC")
        self.journal_max = sy.get("journal_max_use", "200M")
        self.zram = bool(sy.get("zram", True))
        self.bbr = bool(sy.get("bbr", True))
        self.unattended = bool(sy.get("unattended_upgrades", True))
        self.ssh_allow_lan = bool(sy.get("ssh_allow_lan", True))
        self.ssh_allow_tailnet = bool(sy.get("ssh_allow_tailnet", True))

    # ------------------------------------------------------------------ #
    def _server(self, s: dict, where: str) -> dict:
        out = {
            "tag": s.get("tag", "proxy"),
            "address": _need(s, "address", where),
            "port": int(s.get("port", 443)),
            "uuid": _need(s, "uuid", where),
            "encryption": s.get("encryption", "none"),
            "resolved_ip": s.get("resolved_ip", "").strip(),
            "path": s.get("path", "/"),
            "host": s.get("host", "") or s.get("address"),
            "mode": s.get("mode", "auto"),
            "x_padding": s.get("x_padding", ""),
            "security": s.get("security", "tls"),
            "sni": s.get("sni", "") or s.get("address"),
            "fingerprint": s.get("fingerprint", "chrome"),
            "alpn": s.get("alpn", ["h2", "http/1.1"]),
            "allow_insecure": bool(s.get("allow_insecure", False)),
            "public_key": s.get("public_key", ""),
            "short_id": s.get("short_id", ""),
            "spider_x": s.get("spider_x", "/"),
        }
        if out["security"] not in ("tls", "reality", "none"):
            raise ConfigError(f"{where}.security must be tls, reality or none")
        if out["mode"] not in ("auto", "packet-up", "stream-up", "stream-one"):
            raise ConfigError(
                f"{where}.mode must be auto, packet-up, stream-up or stream-one"
            )
        if out["security"] == "reality" and not out["public_key"]:
            raise ConfigError(f"{where}: security='reality' requires public_key")
        if out["resolved_ip"]:
            _ip(out["resolved_ip"], f"{where}.resolved_ip")
        if out["uuid"].startswith("00000000-0000"):
            raise ConfigError(
                f"{where}.uuid is still the placeholder from gateway.example.toml"
            )
        return out

    # ------------------------------------------------------------------ #
    def clients_by(self, policy: str) -> list[str]:
        return [c["ip"] for c in self.clients if c["policy"] == policy]

    @property
    def is_domain_server(self) -> bool:
        try:
            ipaddress.ip_address(self.server["address"])
            return False
        except ValueError:
            return True

    @property
    def proxy_sources(self) -> list[str]:
        """Sources that get intercepted, including the tailnet when we proxy
        exit-node egress."""
        s = self.clients_by("proxy")
        if self.ts_enabled and self.ts_proxy_egress:
            s.append(TAILNET_V4)
        return s

    @property
    def bypass_dst(self) -> list[str]:
        return list(RESERVED_DST)


def load(path: str | pathlib.Path) -> Config:
    p = pathlib.Path(path)
    if not p.exists():
        raise ConfigError(
            f"{p} not found. Copy gateway.example.toml to gateway.toml, "
            "or run `gw init`."
        )
    with p.open("rb") as fh:
        try:
            raw = tomllib.load(fh)
        except tomllib.TOMLDecodeError as e:
            raise ConfigError(f"{p}: {e}")
    return Config(raw, p)


if __name__ == "__main__":
    try:
        cfg = load(sys.argv[1] if len(sys.argv) > 1 else "gateway.toml")
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"ok: {len(cfg.clients)} clients, lan {cfg.lan_cidr}, wan {cfg.wan_if}")
