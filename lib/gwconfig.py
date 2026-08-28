"""Load, validate and normalise gateway.toml.

Stdlib only (tomllib is 3.11+; Debian 13 ships 3.13). No pip installs on the
box, which keeps `gw apply` usable on a broken-network gateway.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
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


CRON_SHORTHAND = {
    "@yearly", "@annually", "@monthly", "@weekly", "@daily",
    "@midnight", "@hourly", "@reboot",
}

# Deliberately permissive within each field (ranges, steps, lists, names) but
# strict about the shape: a five-field line, or a known @shorthand. A malformed
# entry in /etc/cron.d is not rejected by cron, it is silently ignored — so the
# job would simply never run and nothing would say why.
_CRON_FIELD = re.compile(r"^[0-9A-Za-z*/,\-]+$")


def _validate_cron(expr: str, where: str) -> None:
    if not expr:
        raise ConfigError(
            f"{where}.schedule is empty. Use five cron fields "
            '("0 4 * * *") or a shorthand like "@daily".'
        )
    if expr.startswith("@"):
        if expr not in CRON_SHORTHAND:
            raise ConfigError(
                f"{where}.schedule {expr!r} is not a known shorthand. "
                f"Expected one of: {', '.join(sorted(CRON_SHORTHAND))}"
            )
        return
    fields = expr.split()
    if len(fields) != 5:
        raise ConfigError(
            f"{where}.schedule {expr!r} has {len(fields)} field(s); cron needs 5 "
            "(minute hour day-of-month month day-of-week)"
        )
    for pos, field in enumerate(fields):
        if not _CRON_FIELD.match(field):
            raise ConfigError(
                f"{where}.schedule field {pos + 1} ({field!r}) contains "
                "characters cron will not accept"
            )
    if "%" in expr:
        raise ConfigError(
            f"{where}.schedule contains '%', which cron treats as a newline"
        )


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
        # ---- performance (parsed before outbounds, which consume it) ----------------------------------------------------
        perf = raw.get("performance", {})
        # Xray's per-connection buffer, in KB. Left unset by default: shrinking
        # it caps throughput on a high-latency path (the window has to hold a
        # bandwidth-delay product, and a censored route is usually long), and
        # picking a number without measuring the specific link is how you make
        # things slower while believing you tuned them. -1 means "leave Xray's
        # own default alone".
        self.buffer_size_kb = int(perf.get("buffer_size_kb", -1))
        # Applied to outbound sockets. BBR helps most on a lossy path, which is
        # what a censored route usually is.
        self.tcp_congestion = str(perf.get("tcp_congestion", "bbr"))
        self.tcp_no_delay = bool(perf.get("tcp_no_delay", True))
        # Xray's own concurrency ceiling for the tunnel.
        self.conn_idle = int(perf.get("conn_idle_sec", 300))

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

        # Private ranges that are genuinely reachable here, beyond this LAN.
        # Everything else in RFC1918 arriving from a client is treated as a
        # poisoned DNS answer rather than quietly bypassed — see the ruleset.
        self.extra_local = []
        for c in rt.get("extra_local_networks", []):
            self.extra_local.append(str(_net(c, "routing.extra_local_networks")))
        self.drop_private = bool(rt.get("drop_private_destinations", True))

        # ---- geodata --------------------------------------------------------
        geo = raw.get("geodata", {})
        # Release-asset discovery: every *.dat in the latest release is pulled,
        # so a new rule file appearing upstream arrives on its own.
        self.geo_repo = str(geo.get("repo", "Chocolate4U/Iran-v2ray-rules")).strip("/")
        if self.geo_repo and self.geo_repo.count("/") != 1:
            raise ConfigError(
                f"geodata.repo {self.geo_repo!r} must be owner/name, e.g. "
                "'Chocolate4U/Iran-v2ray-rules'"
            )
        self.geo_url = geo.get(
            "url_template",
            "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/{0}.dat",
        )
        if "{0}" not in self.geo_url:
            raise ConfigError(
                "geodata.url_template must contain {0}, which is replaced with "
                "each file name (geoip, geosite)"
            )
        # Empty means "whatever the release ships". Naming files here pins the
        # set and uses url_template instead of discovery.
        self.geo_files = geo.get("files", [])
        if not self.geo_files and not self.geo_repo:
            raise ConfigError(
                "geodata needs either `repo` (download every .dat in the latest "
                "release) or a non-empty `files` list to use with url_template"
            )
        # A truncated .dat takes the tunnel down, and this runs unattended.
        self.geo_min_bytes = int(geo.get("min_bytes", 102400))

        # ---- bootstrap proxy ------------------------------------------------
        # Only for jobs that need the internet BEFORE the tunnel exists:
        # installing Xray, fetching geodata, apt. Once the gateway is running
        # its own traffic is already proxied and this is unused.
        boot = raw.get("bootstrap", {})
        self.bootstrap_proxy = str(boot.get("socks_proxy", "")).strip()
        if self.bootstrap_proxy:
            ok = ("socks5://", "socks5h://", "socks4://", "http://", "https://")
            if not self.bootstrap_proxy.startswith(ok):
                raise ConfigError(
                    f"bootstrap.socks_proxy {self.bootstrap_proxy!r} needs a scheme, "
                    f"one of: {', '.join(ok)}. Prefer socks5h:// so DNS is resolved "
                    "at the proxy rather than locally."
                )

        # ---- dns ------------------------------------------------------------
        dns = raw.get("dns", {})
        self.dns_port = int(dns.get("adguard_port", 53))
        self.ui_port = int(dns.get("adguard_ui_port", 3000))
        self.up_proxied = dns.get("upstreams_proxied", ["https://1.1.1.1/dns-query"])
        self.up_direct = dns.get("upstreams_direct", ["1.1.1.1"])
        self.direct_suffixes = dns.get("direct_suffixes", ["ir"])
        self.bootstrap = dns.get("bootstrap", ["1.1.1.1"])
        # Redirect plain DNS from LAN clients to AdGuard, whatever they are
        # configured to use. Only catches queries that actually traverse this
        # box: a client pointed at the router resolves over the local segment
        # and never reaches us.
        self.dns_intercept = bool(dns.get("intercept", True))
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

        # ---- custom routing -------------------------------------------------
        # Raw Xray routing rules spliced into the generated pipeline. A TOML
        # table maps one-to-one onto Xray's rule JSON, so the table *is* the
        # rule; `position` is the only key the gateway consumes.
        self.routes: list[dict] = []
        matchers = ("domain", "ip", "port", "sourcePort", "network", "source",
                    "user", "inboundTag", "protocol", "attrs")
        for i, r in enumerate(raw.get("route", [])):
            where = f"route[{i}]"
            if not isinstance(r, dict):
                raise ConfigError(f"{where} must be a table")
            position = r.get("position", "before")
            if position not in ("first", "before", "after"):
                raise ConfigError(
                    f"{where}.position must be 'first' (before every other rule), "
                    "'before' (before the geo split, the default) or 'after' "
                    "(after the geo split)"
                )
            if "json" in r:
                try:
                    rule = json.loads(r["json"])
                except ValueError as e:
                    raise ConfigError(f"{where}.json: not valid JSON — {e}")
                if not isinstance(rule, dict):
                    raise ConfigError(f"{where}.json must be a single rule object")
            else:
                rule = {k: v for k, v in r.items() if k != "position"}

            rule.setdefault("type", "field")
            target = rule.get("outboundTag")
            if "balancerTag" not in rule:
                if not target:
                    raise ConfigError(
                        f"{where} has no outboundTag — say where the matched "
                        f"traffic should go (one of: {', '.join(sorted(self.route_targets))})"
                    )
                if target in self.route_targets:
                    rule["outboundTag"] = self.route_targets[target]
                elif target not in self.route_targets.values():
                    raise ConfigError(
                        f"{where}.outboundTag {target!r} is not a known target. "
                        f"Expected one of: {', '.join(sorted(self.route_targets))}"
                    )
            if not any(k in rule for k in matchers):
                raise ConfigError(
                    f"{where} matches nothing — add at least one of: "
                    f"{', '.join(matchers)}"
                )
            self.routes.append({"position": position, "rule": rule})

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
        # Which policy exit-node traffic gets. Any built-in policy or profile
        # name, so a remote device exiting through this box can be routed
        # exactly like a LAN client — including through a profile's upstreams.
        # Validated after profiles are known; see below.
        self._ts_exit_policy_raw = ts.get(
            "exit_node_policy",
            # Back-compat with the old boolean.
            "proxy" if ts.get("proxy_tailnet_egress", True) else "direct",
        )
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

        if self._ts_exit_policy_raw not in self.policies:
            raise ConfigError(
                f"tailscale.exit_node_policy {self._ts_exit_policy_raw!r} is not "
                f"a known policy. Expected one of: {', '.join(self.policies)}"
            )
        self.ts_exit_policy = self._ts_exit_policy_raw
        # Kept as a derived convenience: is tailnet egress intercepted at all?
        self.ts_proxy_egress = self.ts_exit_policy in self.intercepted

        # ---- scheduled jobs -------------------------------------------------
        # Bash + a cron schedule, rendered into /etc/cron.d. Managed from the
        # CLI or the dashboard, but stored here like everything else, so a
        # rebuilt box comes back with its jobs.
        self.jobs: list[dict] = []
        seen_jobs = set()
        for i, j in enumerate(raw.get("job", [])):
            where = f"job[{i}]"
            name = j.get("name", "")
            if not NAME_RE.match(str(name)):
                raise ConfigError(
                    f"{where}.name {name!r} must be 1-24 chars of lowercase "
                    "letters, digits or dashes"
                )
            if name in seen_jobs:
                raise ConfigError(f"{where}: duplicate job name {name!r}")
            seen_jobs.add(name)

            schedule = str(j.get("schedule", "")).strip()
            _validate_cron(schedule, where)

            script = j.get("script", "")
            if not isinstance(script, str) or not script.strip():
                raise ConfigError(f"{where}.script is empty — nothing to run")

            user = str(j.get("user", "root"))
            if not re.match(r"^[a-z_][a-z0-9_-]*$", user):
                raise ConfigError(f"{where}.user {user!r} is not a valid user name")

            self.jobs.append({
                "name": name,
                "schedule": schedule,
                "script": script,
                "user": user,
                "enabled": bool(j.get("enabled", True)),
                "description": str(j.get("description", "")),
            })

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

        # What the scheduled updater does, if anything. Geodata already has
        # its own daily timer; this covers the parts that otherwise never
        # updated unless somebody remembered to run `gw update` by hand.
        self.auto_update = str(sy.get("auto_update", "services"))
        modes = ("off", "check", "services", "all")
        if self.auto_update not in modes:
            raise ConfigError(
                f"system.auto_update must be one of {', '.join(modes)}, "
                f"not {self.auto_update!r}"
            )
        self.auto_update_schedule = str(sy.get("auto_update_schedule", "weekly"))
        if not self.auto_update_schedule.strip():
            raise ConfigError("system.auto_update_schedule must not be empty")
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
        # Performance knobs, only if the outbound has not set them itself —
        # a pasted outbound stays authoritative about its own transport.
        if self.tcp_congestion:
            sock.setdefault("tcpcongestion", self.tcp_congestion)
        if self.tcp_no_delay:
            sock.setdefault("tcpNoDelay", True)

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
        the traffic. Plus the tailnet when exit-node egress is intercepted."""
        s = [c["ip"] for c in self.clients if c["policy"] in self.intercepted]
        if self.ts_enabled and self.ts_exit_policy in self.intercepted:
            s.append(TAILNET_V4)
        return s

    @property
    def tailnet_blocked(self) -> bool:
        return self.ts_enabled and self.ts_exit_policy == "block"

    @property
    def tailnet_direct(self) -> bool:
        return self.ts_enabled and self.ts_exit_policy == "direct"

    def profile_sources(self, name: str) -> list[str]:
        """Which source addresses this profile applies to. When the profile is
        also the LAN default, that includes every unlisted device; when it is
        the exit-node policy, it includes the tailnet."""
        srcs = self.clients_by(name)
        if self.default_policy == name:
            srcs.append(self.lan_cidr)
        if self.ts_enabled and self.ts_exit_policy == name:
            srcs.append(TAILNET_V4)
        return srcs

    @property
    def bypass_dst(self) -> list[str]:
        """Destinations that must never enter the tunnel: local scopes, the
        tailnet, and RFC1918 as a whole. Used by the output chain, where the
        box's own traffic to a private address is local business."""
        return list(RESERVED_DST)

    @property
    def poisoned_dst(self) -> list[str]:
        """RFC1918 space that is NOT reachable from here.

        A filtering resolver answers a blocked name with a private address
        (10.10.34.34 and relatives). A client then sends real traffic there.
        Bypassing it — which is what treating all of RFC1918 as "local" does —
        drops that traffic into a black hole with no counter and no log, and
        the symptom is "this one site does not load" with everything else fine.

        Computed as RFC1918 minus what is genuinely local, so it can never
        match traffic to this LAN or to a network named in
        routing.extra_local_networks.
        """
        if not self.drop_private:
            return []
        blocks = [ipaddress.ip_network(c) for c in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
        keep = [self.lan] + [ipaddress.ip_network(c) for c in self.extra_local]
        for local in keep:
            out = []
            for block in blocks:
                if local.subnet_of(block):
                    out.extend(block.address_exclude(local))
                elif not block.subnet_of(local):
                    out.append(block)
            blocks = out
        return [str(b) for b in sorted(blocks, key=lambda n: (n.network_address, n.prefixlen))]


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
