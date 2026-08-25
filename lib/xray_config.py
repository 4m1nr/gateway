"""Build the Xray config from gateway.toml.

Xray's config is JSON with conditional blocks and generated arrays, so this is
a builder rather than a text template — string-templating JSON is how you end
up shipping a gateway that won't start.
"""

from __future__ import annotations

import json

from gwconfig import Config


def _stream(s: dict, mark: int) -> dict:
    """streamSettings for one XHTTP server, including the SO_MARK that keeps
    Xray's own packets out of the OUTPUT marking rule."""
    xhttp = {
        "host": s["host"],
        "path": s["path"],
        "mode": s["mode"],
    }
    if s["x_padding"]:
        xhttp["xPaddingBytes"] = s["x_padding"]

    stream = {
        "network": "xhttp",
        "security": s["security"],
        "xhttpSettings": xhttp,
        # THE loop guard. Every packet Xray sends carries this mark; the
        # nftables output chain returns early on it. Without this, Xray's own
        # traffic is re-captured by TPROXY and the box wedges instantly.
        "sockopt": {"mark": mark, "tcpFastOpen": True, "domainStrategy": "UseIPv4"},
    }

    if s["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": s["sni"],
            "fingerprint": s["fingerprint"],
            "alpn": s["alpn"],
            "allowInsecure": s["allow_insecure"],
        }
    elif s["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": s["sni"],
            "fingerprint": s["fingerprint"],
            "publicKey": s["public_key"],
            "shortId": s["short_id"],
            "spiderX": s["spider_x"],
        }
    return stream


def _outbound(s: dict, mark: int, tag: str) -> dict:
    return {
        "tag": tag,
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
        "streamSettings": _stream(s, mark),
    }


def _dns(cfg: Config) -> dict:
    servers: list = []
    hosts: dict = {}

    # Pin the server address so the tunnel never depends on DNS to come up.
    for s in (cfg.server, cfg.fallback):
        if s and s["resolved_ip"]:
            hosts[s["address"]] = s["resolved_ip"]

    # The server's own domain resolves via a direct resolver — it must be
    # reachable before the tunnel exists.
    domain_servers = [f"domain:{cfg.server['address']}"] if cfg.is_domain_server else []
    if cfg.fallback and not cfg.fallback["resolved_ip"]:
        domain_servers.append(f"domain:{cfg.fallback['address']}")
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
    outs = [_outbound(cfg.server, cfg.outbound_mark, "proxy")]
    if cfg.fallback:
        outs.append(_outbound(cfg.fallback, cfg.outbound_mark, "fallback"))
    outs += [
        {
            "tag": "direct",
            "protocol": "freedom",
            "settings": {"domainStrategy": "UseIPv4"},
            "streamSettings": {"sockopt": {"mark": cfg.outbound_mark}},
        },
        {"tag": "block", "protocol": "blackhole", "settings": {}},
    ]
    return outs


def _routing(cfg: Config) -> dict:
    # Must come first: API traffic has to reach the API handler before any
    # other rule can claim it.
    rules: list = [
        {"type": "field", "inboundTag": ["api"], "outboundTag": "api"}
    ]

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

    if cfg.direct_geosite:
        rules.append(
            {"type": "field", "domain": cfg.direct_geosite, "outboundTag": "direct"}
        )
    if cfg.direct_geoip:
        rules.append({"type": "field", "ip": cfg.direct_geoip, "outboundTag": "direct"})

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
            "levels": {"0": {"handshake": 4, "connIdle": 300, "uplinkOnly": 0,
                             "downlinkOnly": 0}},
            "system": {"statsOutboundUplink": True, "statsOutboundDownlink": True},
        },
        "stats": {},
    }
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
