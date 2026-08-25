"""Build the Xray config from gateway.toml.

Upstream outbounds are taken verbatim from the config — the gateway does not
model protocols or transports, so anything Xray supports works. It only owns
the tag (routing references it) and sockopt.mark (the loop guard), both
enforced in gwconfig when the outbound is loaded.

Everything else here — inbounds, DNS, routing — is generated, because it is
derived from the rest of gateway.toml rather than supplied.
"""

from __future__ import annotations

import json

from gwconfig import Config


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _direct_sockopt(cfg: Config) -> dict:
    sock = {"mark": cfg.outbound_mark}
    if cfg.tcp_congestion:
        sock["tcpcongestion"] = cfg.tcp_congestion
    if cfg.tcp_no_delay:
        sock["tcpNoDelay"] = True
    return sock


def _dns(cfg: Config) -> dict:
    servers: list = []
    hosts: dict = {}

    # Pin server addresses so the tunnel never depends on DNS to come up.
    for s in [cfg.server, cfg.fallback, *cfg.upstreams.values()]:
        if s and s["resolved_ip"] and s["address"]:
            hosts[s["address"]] = s["resolved_ip"]

    # The server's own domain resolves via a direct resolver — it must be
    # reachable before the tunnel exists.
    domain_servers = [f"domain:{cfg.server['address']}"] if cfg.is_domain_server else []
    # Upstreams reached by name need the same treatment: their hostname must
    # resolve before any tunnel exists.
    others = [cfg.fallback] if cfg.fallback else []
    others += list(cfg.upstreams.values())
    for spec in others:
        addr = spec["address"]
        if addr and not spec["resolved_ip"] and not _is_ip(addr):
            domain_servers.append(f"domain:{addr}")
    if domain_servers:
        servers.append(
            {
                "address": cfg.up_direct[0],
                "domains": domain_servers,
                "skipFallback": False,
            }
        )

    # Domestic names: direct resolver, and only trust answers that look domestic.
    domestic = list(cfg.direct_geosite) + [f"domain:{d}" for d in cfg.direct_suffixes]
    for res in cfg.up_direct:
        servers.append(
            {
                "address": res,
                "domains": domestic,
                "expectIPs": cfg.direct_geoip,
                "skipFallback": True,
            }
        )

    # Everything else: DoH, which rides the tunnel like the rest of our traffic.
    servers.extend(cfg.up_proxied)

    dns = {
        "servers": servers,
        "queryStrategy": "UseIPv4" if cfg.ipv6_mode == "off" else "UseIP",
        "disableCache": False,
        "tag": "dns-in",
    }
    if hosts:
        dns["hosts"] = hosts
    return dns


def _inbounds(cfg: Config) -> list:
    sniffing = {
        "enabled": True,
        # TPROXY hands us an IP, nothing more. Sniffing recovers the hostname
        # so geosite rules can actually match.
        "destOverride": ["http", "tls", "quic"],
        "routeOnly": True,
    }
    return [
        {
            # Loopback-only stats API. `gw check` uses the per-outbound
            # counters to prove which path a flow actually took.
            "tag": "api",
            "listen": "127.0.0.1",
            "port": cfg.api_port,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"},
        },
        {
            "tag": "tproxy-in",
            "port": cfg.tproxy_port,
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
            "sniffing": sniffing,
        },
        {
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": cfg.socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True},
            "sniffing": sniffing,
        },
        {
            "tag": "http-in",
            "listen": "127.0.0.1",
            "port": cfg.http_port,
            "protocol": "http",
            "settings": {},
            "sniffing": sniffing,
        },
    ]


def _outbounds(cfg: Config) -> list:
    # Verbatim, tag and loop-guard mark already enforced at load time.
    outs = [cfg.server["outbound"]]
    if cfg.fallback:
        outs.append(cfg.fallback["outbound"])
    for spec in cfg.upstreams.values():
        outs.append(spec["outbound"])
    outs += [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {
                "domainStrategy": "UseIPv4" if cfg.ipv6_mode == "off" else "UseIP"
            },
            # Generated, so the loop guard and the performance settings are
            # applied here rather than at load time. This outbound carries the
            # domestic-direct half of the split, so it wants the same tuning.
            "streamSettings": {"sockopt": _direct_sockopt(cfg)},
        },
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]
    return outs


def _routing(cfg: Config) -> dict:
    def custom(position: str) -> list:
        return [r["rule"] for r in cfg.routes if r["position"] == position]

    # Must come first: API traffic has to reach the API handler before any
    # other rule can claim it.
    rules: list = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
    ]

    # position = "first": ahead of even the per-client policy rules. This is
    # where a hard block belongs — "never let anything reach this ip:port",
    # regardless of which device asked.
    rules += custom("first")

    if cfg.block_geosite:
        rules.append(
            {"type": "field", "domain": cfg.block_geosite, "outboundTag": "block"}
        )
    if cfg.block_bittorrent:
        rules.append(
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "block"}
        )

    blocked = cfg.clients_by("block")
    if blocked:
        rules.append({"type": "field", "source": blocked, "outboundTag": "block"})

    # A "direct" client shouldn't reach Xray at all (nftables returns it before
    # TPROXY), but if one is added here without re-applying the firewall, this
    # keeps the intent correct rather than silently proxying it.
    direct_clients = cfg.clients_by("direct")
    if direct_clients:
        rules.append(
            {"type": "field", "source": direct_clients, "outboundTag": "direct"}
        )

    # Profile exceptions come before the global geo split: "send corp.example.ir
    # through the work upstream" has to beat "all .ir goes direct", because the
    # per-device rule is the more specific statement.
    for name, profile in cfg.profiles.items():
        sources = cfg.profile_sources(name)
        if not sources:
            continue
        for route in profile["routes"]:
            if route["domains"]:
                rules.append({
                    "type": "field", "source": sources,
                    "domain": route["domains"], "outboundTag": route["tag"],
                })
            if route["ips"]:
                rules.append({
                    "type": "field", "source": sources,
                    "ip": route["ips"], "outboundTag": route["tag"],
                })

    # position = "before" (the default): after per-client policy, ahead of the
    # global geo split — so a custom rule wins over "all .ir goes direct".
    rules += custom("before")

    if cfg.direct_geosite:
        rules.append(
            {"type": "field", "domain": cfg.direct_geosite, "outboundTag": "direct"}
        )
    if cfg.direct_geoip:
        rules.append({"type": "field", "ip": cfg.direct_geoip, "outboundTag": "direct"})

    # position = "after": the geo split has already had its say; this catches
    # what it did not claim, before any of the fallthrough defaults.
    rules += custom("after")

    # Then each profile's fallthrough. After the geo rules, so a profile client
    # still gets the domestic-direct split for everything its own rules did not
    # claim.
    for name, profile in cfg.profiles.items():
        sources = cfg.profile_sources(name)
        if sources:
            rules.append({
                "type": "field", "source": sources,
                "outboundTag": profile["base"],
            })

    routing = {"domainStrategy": cfg.domain_strategy, "rules": rules}

    if cfg.fallback:
        routing["balancers"] = [
            {
                "tag": "tunnel",
                "selector": ["proxy", "fallback"],
                "strategy": {"type": "leastPing"},
            }
        ]
        rules.append({"type": "field", "network": "tcp,udp", "balancerTag": "tunnel"})
    else:
        rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})

    return routing


def build(cfg: Config) -> dict:
    conf = {
        "log": {"loglevel": cfg.log_level},
        "api": {"tag": "api", "services": ["StatsService"]},
        "dns": _dns(cfg),
        "inbounds": _inbounds(cfg),
        "outbounds": _outbounds(cfg),
        "routing": _routing(cfg),
        "policy": {
            "levels": {
                "0": {
                    "handshake": 4,
                    "connIdle": cfg.conn_idle,
                    "uplinkOnly": 0,
                    "downlinkOnly": 0,
                }
            },
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True},
        },
        "stats": {},
    }
    if cfg.buffer_size_kb >= 0:
        conf["policy"]["levels"]["0"]["bufferSize"] = cfg.buffer_size_kb

    if cfg.fallback:
        conf["burstObservatory"] = {
            "subjectSelector": ["proxy", "fallback"],
            "pingConfig": {
                "destination": cfg.probe_url,
                "interval": "5m",
                "timeout": "10s",
                "sampling": 3,
            },
        }
    return conf


def render(cfg: Config) -> str:
    return json.dumps(build(cfg), indent=2) + "\n"
