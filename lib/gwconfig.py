"""Load, validate and normalise gateway.toml.

Stdlib only (tomllib is 3.11+; Debian 13 ships 3.13). No pip installs on the
box, which keeps `gw apply` usable on a broken-network gateway.
"""

from __future__ import annotations

import ipaddress
import json
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

BUILTIN_POLICIES = ("proxy", "direct", "block")
# Profile and upstream names become Xray outbound tags and appear in the
# generated config, so keep them boring.
NAME_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9-]{0,23}$")


class ConfigError(Exception):
    pass


def _outbound_address(ob: dict) -> str | None:
    """Best-effort server address, for DNS pinning only.

    Covers the shapes Xray actually uses (vnext for vless/vmess, servers for
    trojan/shadowsocks/socks). Anything else returns None, and the config can
    name the host explicitly with `server_domain`.
    """
    settings = ob.get("settings")
    if not isinstance(settings, dict):
        return None
    for key in ("vnext", "servers"):
        entries = settings.get(key)
        if isinstance(entries, list) and entries and isinstance(entries[0], dict):
            addr = entries[0].get("address")
            if isinstance(addr, str) and addr:
                return addr
    return None


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
        self.server = self._load_outbound(
            _need(xr, "outbound", "xray"), "xray.outbound", "proxy"
        )
        fb = xr.get("fallback", {})
        self.fallback = (
            self._load_outbound(fb, "xray.fallback", "fallback")
            if fb.get("enabled") else None
        )

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

        # ---- upstreams ------------------------------------------------------
        # Extra Xray servers that profiles can route selected traffic through
        # (a work VPN, a second exit country, ...).
        self.upstreams: dict[str, dict] = {}
        for i, u in enumerate(raw.get("upstream", [])):
            where = f"upstream[{i}]"
            name = u.get("name", "")
            if not NAME_RE.match(str(name)):
                raise ConfigError(
                    f"{where}.name {name!r} must be 1-24 chars of lowercase "
                    "letters, digits or dashes"
                )
            if name in self.upstreams:
                raise ConfigError(f"{where}: duplicate upstream name {name!r}")
            if name in BUILTIN_POLICIES:
                raise ConfigError(
                    f"{where}.name {name!r} is reserved — it is a built-in route target"
                )
            self.upstreams[name] = self._load_outbound(u, where, f"up-{name}")

        # Where a profile rule may send traffic.
        self.route_targets = {
            **{n: s["tag"] for n, s in self.upstreams.items()},
            "proxy": "proxy",
            "direct": "direct",
            "block": "block",
        }

        # ---- profiles -------------------------------------------------------
        # A profile is a built-in policy plus destination-specific exceptions:
        # "behave like `base`, except send these domains/networks via X".
        self.profiles: dict[str, dict] = {}
        for i, pr in enumerate(raw.get("profile", [])):
            where = f"profile[{i}]"
            name = pr.get("name", "")
            if not NAME_RE.match(str(name)):
                raise ConfigError(
                    f"{where}.name {name!r} must be 1-24 chars of lowercase "
                    "letters, digits or dashes"
                )
            if name in BUILTIN_POLICIES:
                raise ConfigError(f"{where}.name {name!r} is a built-in policy name")
            if name in self.upstreams:
                raise ConfigError(
                    f"{where}.name {name!r} is already an upstream name — "
                    "profiles and upstreams share a namespace"
                )
            if name in self.profiles:
                raise ConfigError(f"{where}: duplicate profile name {name!r}")

            base = pr.get("base", "proxy")
            if base not in ("proxy", "direct"):
                raise ConfigError(
                    f"{where}.base must be 'proxy' or 'direct' (got {base!r}). "
                    "A profile that blocked everything would have nothing to route."
                )

            routes = []
            for j, r in enumerate(pr.get("route", [])):
                rwhere = f"{where}.route[{j}]"
                via = r.get("via")
                if via not in self.route_targets:
                    known = ", ".join(sorted(self.route_targets))
                    raise ConfigError(
                        f"{rwhere}.via {via!r} is not a known target. "
                        f"Expected one of: {known}"
                    )
                domains = list(r.get("domains", []))
                ips = list(r.get("ips", []))
                if not domains and not ips:
                    raise ConfigError(
                        f"{rwhere} matches nothing — give it `domains`, `ips`, or both"
                    )
                for cidr in ips:
                    if not str(cidr).startswith("geoip:"):
                        _net(cidr, f"{rwhere}.ips")
                routes.append(
                    {"via": via, "tag": self.route_targets[via],
                     "domains": domains, "ips": ips}
                )
            if not routes:
                raise ConfigError(
                    f"{where} has no [[profile.route]] rules, so it is just "
                    f"policy = {base!r}. Use the built-in policy instead."
                )
            self.profiles[name] = {"base": base, "routes": routes}

        self.policies = tuple(BUILTIN_POLICIES) + tuple(self.profiles)
        # Every profile needs its traffic in front of Xray to be split at all.
        self.intercepted = {"proxy", *self.profiles}

        # ---- clients --------------------------------------------------------
        # A bare `default_policy = ...` written after any [table] is parsed as a
        # key of THAT table, so it silently does nothing. That is exactly what
        # happened in the first version of the example config, and the bug was
        # invisible because the ignored value matched the fallback. Reject it
        # loudly rather than quietly using the wrong policy.
        for name, table in raw.items():
            if name != "policy" and isinstance(table, dict) and "default_policy" in table:
                raise ConfigError(
                    f"default_policy is inside [{name}], where TOML makes it "
                    f"{name}.default_policy and nothing reads it. Move it to:\n"
                    '\n  [policy]\n  default = "proxy"\n'
                )
        self.default_policy = raw.get("policy", {}).get(
            "default", raw.get("default_policy", "proxy")
        )
        if self.default_policy not in self.policies:
            raise ConfigError(
                f"policy.default must be one of {', '.join(self.policies)}, "
                f"not {self.default_policy!r}"
            )

        self.clients = []
        seen = set()
        for i, c in enumerate(raw.get("client", [])):
            where = f"client[{i}]"
            ip = _ip(_need(c, "ip", where), f"{where}.ip")
            pol = c.get("policy", self.default_policy)
            if pol not in self.policies:
                raise ConfigError(
                    f"{where}.policy {pol!r} is not defined. Known policies: "
                    f"{', '.join(self.policies)}"
                )
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

        # ---- web ------------------------------------------------------------
        w = raw.get("web", {})
        self.web_enabled = bool(w.get("enabled", True))
        self.web_listen = w.get("listen", "0.0.0.0")
        self.web_port = int(w.get("port", 8088))
        if not 1 <= self.web_port <= 65535:
            raise ConfigError(f"web.port {self.web_port} is out of range")
        if self.web_port in (self.dns_port, self.ui_port, self.tproxy_port,
                             self.socks_port, self.http_port, self.api_port):
            raise ConfigError(
                f"web.port {self.web_port} collides with another gateway service"
            )
        self.web_tls = bool(w.get("tls", True))
        self.web_cert = w.get("cert", "/etc/gateway/web.crt")
        self.web_key = w.get("key", "/etc/gateway/web.key")
        if self.web_tls and not (self.web_cert and self.web_key):
            raise ConfigError("web.tls is on but web.cert/web.key are not set")

        # Default to the LAN plus the tailnet: the dashboard can rewrite the
        # firewall, so it is never reachable from anywhere by accident.
        allow = w.get("allow_cidrs") or [self.lan_cidr, TAILNET_V4]
        self.web_allow: list[str] = []
        for c in allow:
            net = _net(c, "web.allow_cidrs")
            if net.prefixlen == 0:
                raise ConfigError(
                    "web.allow_cidrs contains 0.0.0.0/0, which would expose the "
                    "dashboard to everything the box can reach. List real networks."
                )
            self.web_allow.append(str(net))
        self.session_hours = int(w.get("session_hours", 12))
        self.max_failed_logins = int(w.get("max_failed_logins", 5))
        self.lockout_minutes = int(w.get("lockout_minutes", 15))

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
    def _load_outbound(self, spec: dict, where: str, tag: str) -> dict:
        """Load a complete Xray outbound object, verbatim.

        The gateway does not model protocols or transports — whatever Xray
        supports, you can paste. What it does own, and always overrides, is the
        part that makes the outbound safe to use here:

          tag      routing rules reference it, so the gateway assigns it
          sockopt.mark  the loop guard; without it the box routes its own
                        tunnel traffic back into the tunnel and wedges
        """
        inline, path = spec.get("json"), spec.get("file")
        if bool(inline) == bool(path):
            raise ConfigError(
                f"{where}: set exactly one of `file` (path to a .json outbound) "
                "or `json` (the outbound inline)"
            )

        if path:
            src = (self.path.parent / path).resolve()
            try:
                text = src.read_text()
            except OSError as e:
                raise ConfigError(f"{where}.file: {e}")
            origin = str(src)
        else:
            text, origin = inline, f"{where}.json"

        try:
            ob = json.loads(text)
        except ValueError as e:
            raise ConfigError(f"{origin}: not valid JSON — {e}")
        if not isinstance(ob, dict):
            raise ConfigError(
                f"{origin}: expected a single outbound object "
                '(starting with {"protocol": ...}), not a list or bare value'
            )
        if "00000000-0000-0000-0000-000000000000" in text:
            raise ConfigError(
                f"{origin} still contains the placeholder UUID from the example "
                "outbound. Put your real server details in it."
            )
        if not isinstance(ob.get("protocol"), str):
            raise ConfigError(f'{origin}: outbound has no "protocol" field')
        if "outbounds" in ob or "inbounds" in ob:
            raise ConfigError(
                f"{origin}: this looks like a whole Xray config. Use just one "
                'entry from its "outbounds" array.'
            )

        if ob.get("tag") not in (None, tag):
            # Not fatal, but silently renaming would be worse: routing rules
            # generated elsewhere reference the tag we assign.
            print(
                f"note: {origin} has tag {ob['tag']!r}; the gateway uses {tag!r}",
                file=sys.stderr,
            )
        ob["tag"] = tag

        stream = ob.setdefault("streamSettings", {})
        if not isinstance(stream, dict):
            raise ConfigError(f"{origin}: streamSettings must be an object")
        sock = stream.setdefault("sockopt", {})
        if not isinstance(sock, dict):
            raise ConfigError(f"{origin}: streamSettings.sockopt must be an object")
        if "mark" in sock and int(sock["mark"]) != self.outbound_mark:
            raise ConfigError(
                f"{origin}: sockopt.mark is {sock['mark']}, but the firewall "
                f"exempts {self.outbound_mark}. A different mark means Xray's own "
                "packets get re-captured by TPROXY and the gateway deadlocks. "
                "Remove it, or change xray.outbound_mark to match."
            )
        sock["mark"] = self.outbound_mark
        sock.setdefault(
            "domainStrategy", "UseIPv4" if self.ipv6_mode == "off" else "UseIP"
        )

        server_ip = str(spec.get("server_ip", "")).strip()
        if server_ip:
            _ip(server_ip, f"{where}.server_ip")
        return {
            "tag": tag,
            "outbound": ob,
            "address": spec.get("server_domain") or _outbound_address(ob),
            "resolved_ip": server_ip,
            "origin": origin,
        }

    # ------------------------------------------------------------------ #
    def clients_by(self, policy: str) -> list[str]:
        return [c["ip"] for c in self.clients if c["policy"] == policy]

    @property
    def is_domain_server(self) -> bool:
        addr = self.server["address"]
        if not addr:
            return False
        try:
            ipaddress.ip_address(addr)
            return False
        except ValueError:
            return True

    @property
    def proxy_sources(self) -> list[str]:
        """Sources that get intercepted: plain proxy clients and every profile
        client, since splitting a profile by destination requires Xray to see
        the traffic. Plus the tailnet when exit-node egress is proxied."""
        s = [c["ip"] for c in self.clients if c["policy"] in self.intercepted]
        if self.ts_enabled and self.ts_proxy_egress:
            s.append(TAILNET_V4)
        return s

    def profile_sources(self, name: str) -> list[str]:
        """Which source addresses this profile applies to. When the profile is
        also the LAN default, that includes every unlisted device."""
        srcs = self.clients_by(name)
        if self.default_policy == name:
            srcs.append(self.lan_cidr)
        return srcs

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
