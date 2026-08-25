"""Desired AdGuard Home settings, derived from gateway.toml.

AdGuard owns its own YAML (it rewrites and schema-migrates the file), so we do
not template it wholesale — we emit the keys we care about and merge them in.
Anything set through the web UI that we don't name here survives `gw apply`.
"""

from __future__ import annotations

from gwconfig import Config


def overrides(cfg: Config) -> dict:
    # Domestic names go to the direct resolvers; everything else to DoH, which
    # rides the tunnel because AdGuard's own egress is captured by the OUTPUT
    # chain like any other local process.
    upstreams: list[str] = []
    for suffix in cfg.direct_suffixes:
        for res in cfg.up_direct:
            upstreams.append(f"[/{suffix}/]{res}")
    upstreams.extend(cfg.up_proxied)

    persistent = []
    for i, c in enumerate(cfg.clients):
        persistent.append(
            {
                "name": c["name"],
                "ids": [c["ip"]],
                "tags": [],
                "use_global_settings": True,
                "use_global_blocked_services": True,
                "filtering_enabled": c["policy"] != "direct",
                "safebrowsing_enabled": False,
                "parental_enabled": False,
                "blocked_services": {"ids": [], "schedule": {"time_zone": cfg.timezone}},
                "upstreams": [],
                "ignore_querylog": False,
                "ignore_statistics": False,
            }
        )

    filters = [
        {
            "enabled": True,
            "url": url,
            "name": url.rsplit("/", 1)[-1],
            "id": 1000 + i,
        }
        for i, url in enumerate(cfg.blocklists)
    ]

    return {
        "http": {
            # Reachable on the LAN and over Tailscale; the input chain is what
            # keeps it off anything else.
            "address": f"0.0.0.0:{cfg.ui_port}",
        },
        "dns": {
            "bind_hosts": ["0.0.0.0"],
            "port": cfg.dns_port,
            "upstream_dns": upstreams,
            "bootstrap_dns": cfg.bootstrap,
            # Deliberately empty. Falling back to the domestic resolvers means
            # that whenever DoH is slow — which is exactly when the network is
            # being interfered with — AdGuard asks a resolver that lies, and
            # cheerfully caches the lie. A poisoned answer pointing at private
            # space (10.10.34.34 and friends) is worse than no answer: that
            # address is in bypass_dst, so the connection is never intercepted,
            # goes out direct, and dies mid-TLS-handshake looking like a broken
            # tunnel. Fail closed on DNS, like everything else here.
            "fallback_dns": [],
            "upstream_mode": "load_balance",
            "ratelimit": 0,
            "enable_dnssec": True,
            "cache_size": 8388608,
            "cache_ttl_min": 60,
            "aaaa_disabled": cfg.ipv6_mode == "off",
            "local_ptr_upstreams": cfg.up_direct,
        },
        "querylog": {
            "enabled": True,
            # Thin-client flash is small and slow; keep retention short.
            "interval": f"{cfg.querylog_days * 24}h",
            "size_memory": 1000,
        },
        "statistics": {
            "enabled": True,
            "interval": f"{cfg.statslog_days * 24}h",
        },
        "filters": filters,
        "clients": {"persistent": persistent},
        "filtering": {"protection_enabled": True, "filtering_enabled": True},
    }
