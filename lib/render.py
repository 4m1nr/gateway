"""Render every generated file into build/, mirroring the target filesystem.

build/ is a staging tree: `gw apply` diffs it against / and installs. Nothing
is written to the live system from here, so `gw render` is always safe to run.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import shutil
import sys

import adguard
import gwconfig
import xray_config
from gwconfig import Config

ROOT = pathlib.Path(__file__).resolve().parent.parent
TPL = ROOT / "templates"
RT_TABLE = 100

# Files installed executable.
EXECUTABLE = {"usr/local/lib/gateway/ip-rules.sh",
              "usr/local/lib/gateway/health.sh",
              "usr/local/lib/gateway/geoupdate.sh",
              "usr/local/lib/gateway/ts-bypass.sh",
              "usr/local/lib/gateway/xray-update.sh",
              "usr/local/lib/gateway/adguard-update.sh",
              "usr/local/lib/gateway/web-action.py"}


def subst(text: str, mapping: dict[str, str]) -> str:
    for key, val in mapping.items():
        text = text.replace("{{" + key + "}}", val)
    leftover = [
        line for line in text.splitlines() if "{{" in line and "}}" in line
    ]
    if leftover:
        raise RuntimeError(f"unsubstituted placeholder: {leftover[0].strip()}")
    return text


def nft_elements(items: list[str], indent: int = 8) -> str:
    if not items:
        return ""
    pad = " " * indent
    return f"{pad}elements = {{ {', '.join(items)} }}\n"


def render_nft(cfg: Config) -> str:
    tpl = (TPL / "gateway.nft.tmpl").read_text()

    if cfg.ipv6_mode == "off":
        v6_pre = '        meta nfproto ipv6 iifname != "tailscale0" drop\n'
        v6_out = '        meta nfproto ipv6 return\n'
        v6_fwd = ('        meta nfproto ipv6 iifname != "tailscale0" '
                  'oifname != "tailscale0" drop\n')
    else:
        v6_pre = v6_out = v6_fwd = ""

    # Always rendered empty. The tailscaled exemption is a cgroup match, and
    # nftables resolves the cgroup path to an ID at insertion time — at boot
    # tailscaled has no cgroup yet, so the rule is added later by
    # gw-tailscale-exception.service instead of being baked in here.
    exceptions = ""

    # The catch-all that makes "point your gateway here and you are proxied"
    # true. It matches $LAN in the forward path only, so it applies to exactly
    # the devices that opted in — a device using the router as its gateway
    # never sends a packet through this chain.
    # A profile is intercepted exactly like a plain proxy client: splitting
    # traffic by destination requires Xray to see it.
    if cfg.default_policy in cfg.intercepted:
        pre_default = (
            "        meta l4proto { tcp, udp } ip saddr $LAN {{DNS_EXCLUDE}}\\\n"
            "            meta mark set $MARK_TPROXY counter \\\n"
            "            tproxy ip to 127.0.0.1:$TPROXY_PORT accept "
            'comment "lan-intercepted"\n'
        )
        # Same kill switch as for listed clients: if Xray is not listening the
        # TPROXY rule above does not match, and this drop is what stops the
        # packet finding a direct way out.
        fwd_default = (
            '        ip saddr $LAN counter drop comment "killswitch-default"\n'
        )
        post_default = ""
    elif cfg.default_policy == "direct":
        pre_default = "        ip saddr $LAN return\n"
        fwd_default = "        ip saddr $LAN accept\n"
        post_default = "        oifname $WAN ip saddr $LAN masquerade\n"
    else:  # block
        pre_default = "        ip saddr $LAN drop\n"
        fwd_default = ""
        post_default = ""

    poisoned_rule = (
        '        ip daddr @poisoned_dst counter drop comment "poisoned-dns"\n'
        if cfg.poisoned_dst else
        "        # routing.drop_private_destinations = false\n"
    )

    # TPROXY runs at mangle priority (-150) and nat prerouting at dstnat
    # (-100), so an unqualified tproxy rule would swallow port 53 before the
    # redirect below ever ran — leaving dns.intercept enabled and inert.
    dns_exclude = "th dport != 53 " if cfg.dns_intercept else ""

    # Catches clients pointed at a public resolver. One pointed at the router
    # resolves over the local segment and never reaches this box at all — for
    # those, the router's DHCP has to hand out this box as the DNS server.
    if cfg.dns_intercept:
        dns_chain = (
            "    chain dnsintercept {\n"
            "        type nat hook prerouting priority dstnat; policy accept;\n"
            "        # Opted-out clients keep whatever resolver they chose.\n"
            "        ip saddr @direct_clients return\n"
            "        ip daddr $BOX return\n"
            "        ip saddr $LAN meta l4proto { tcp, udp } th dport 53 \\\n"
            f"            dnat ip to $BOX:{cfg.dns_port}\n"
            "    }\n"
        )
    else:
        dns_chain = "    # dns.intercept = false\n"

    ssh_rule = "        ip saddr $LAN tcp dport 22 accept\n" if cfg.ssh_allow_lan else ""
    ui_rule = f"        ip saddr $LAN tcp dport {cfg.ui_port} accept\n"

    # First of the dashboard's three gates. The app re-checks the peer itself;
    # this is what stops a packet from an unlisted source arriving at all.
    web_rule = ""
    if cfg.web_enabled:
        allowed = ", ".join(cfg.web_allow)
        web_rule = (
            f"        # web dashboard, restricted to web.allow_cidrs\n"
            f"        ip saddr {{ {allowed} }} tcp dport {cfg.web_port} accept\n"
        )

    pre_default = pre_default.replace("{{DNS_EXCLUDE}}", dns_exclude)

    return subst(
        tpl,
        {
            "CONFIG_PATH": str(cfg.path),
            "GENERATED_AT": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
            "WAN_IF": cfg.wan_if,
            "LAN_CIDR": cfg.lan_cidr,
            "BOX_IP": cfg.box_ip,
            "ROUTER": cfg.router,
            "TPROXY_PORT": str(cfg.tproxy_port),
            "MARK_TPROXY": "1",
            "MARK_XRAY": str(cfg.outbound_mark),
            "DNS_PORT": str(cfg.dns_port),
            "ELEM_PROXY": nft_elements(cfg.proxy_sources),
            "ELEM_DIRECT": nft_elements(
                cfg.clients_by("direct")
                + ([gwconfig.TAILNET_V4] if cfg.tailnet_direct else [])
            ),
            "ELEM_BLOCKED": nft_elements(
                cfg.clients_by("block")
                + ([gwconfig.TAILNET_V4] if cfg.tailnet_blocked else [])
            ),
            "ELEM_BYPASS": nft_elements(cfg.bypass_dst),
            "ELEM_POISONED": nft_elements(cfg.poisoned_dst),
            "ELEM_EXCEPTIONS": exceptions,
            "IPV6_PREROUTING": v6_pre,
            "IPV6_OUTPUT": v6_out,
            "IPV6_FORWARD": v6_fwd,
            "PREROUTING_DEFAULT": pre_default,
            "FORWARD_DEFAULT": fwd_default,
            "POSTROUTING_DEFAULT": post_default,
            "POISONED_RULE": poisoned_rule,
            "DNS_INTERCEPT": dns_chain,
            "DNS_EXCLUDE": dns_exclude,
            "INPUT_SSH": ssh_rule,
            "INPUT_UI": ui_rule,
            "INPUT_WEB": web_rule,
        },
    )


def render_sysctl(cfg: Config) -> str:
    if cfg.ipv6_mode == "off":
        v6 = (
            "# IPv6 off on the LAN side only. A blanket all.disable_ipv6 would\n"
            "# break Tailscale, which uses IPv6 for its own tailnet addressing.\n"
            f"net.ipv6.conf.{cfg.wan_if}.disable_ipv6 = 1\n"
            f"net.ipv6.conf.{cfg.wan_if}.accept_ra = 0\n"
        )
    else:
        v6 = "net.ipv6.conf.all.forwarding = 1\n"
    bbr = ("net.core.default_qdisc = fq\n"
           "net.ipv4.tcp_congestion_control = bbr\n") if cfg.bbr else ""
    return subst(
        (TPL / "sysctl.conf.tmpl").read_text(),
        {"WAN_IF": cfg.wan_if, "IPV6_SYSCTL": v6, "BBR_SYSCTL": bbr},
    )


def render_network(cfg: Config) -> str:
    v6 = ("IPv6AcceptRA=no\nLinkLocalAddressing=no\n"
          if cfg.ipv6_mode == "off" else "IPv6AcceptRA=yes\n")
    return subst(
        (TPL / "wan.network.tmpl").read_text(),
        {
            "WAN_IF": cfg.wan_if,
            "BOX_IP": cfg.box_ip,
            "ROUTER": cfg.router,
            "PREFIX_LEN": str(cfg.prefix_len),
            "ROUTER": cfg.router,
            "IPV6_NETWORK": v6,
        },
    )


def render_env(cfg: Config) -> str:
    """Shell-sourceable settings for the helper scripts.

    Every value is quoted: this file is `.`-sourced, so an unquoted value
    containing a space (GEO_FILES, a proxy URL with odd characters) would be
    parsed as a command. Readers that want a single value should source the
    file rather than grepping it.
    """
    pairs = [
        ("REPO", str(ROOT)),
        # Only used by jobs that need the internet before the tunnel exists;
        # unused once the gateway carries its own traffic.
        ("BOOTSTRAP_PROXY", cfg.bootstrap_proxy),
        ("GEO_REPO", cfg.geo_repo),
        ("GEO_URL_TEMPLATE", cfg.geo_url),
        ("GEO_FILES", " ".join(cfg.geo_files)),
        ("GEO_MIN_BYTES", cfg.geo_min_bytes),
        ("WAN_IF", cfg.wan_if),
        ("LAN_CIDR", cfg.lan_cidr),
        ("BOX_IP", cfg.box_ip),
        ("ROUTER", cfg.router),
        ("TPROXY_PORT", cfg.tproxy_port),
        ("SOCKS_PORT", cfg.socks_port),
        ("HTTP_PORT", cfg.http_port),
        ("API_PORT", cfg.api_port),
        ("MARK_TPROXY", 1),
        ("MARK_XRAY", cfg.outbound_mark),
        ("RT_TABLE", RT_TABLE),
        ("PROBE_URL", cfg.probe_url),
        ("PROBE_TIMEOUT", cfg.probe_timeout),
        ("DOMESTIC_PROBE_URL", cfg.domestic_probe_url),
        ("INTERVAL", cfg.health_interval),
        ("RESTART_AFTER", cfg.restart_after),
        ("FALLBACK_AFTER", cfg.fallback_after),
        ("LIFELINE_MIN", cfg.ts_lifeline_min if cfg.ts_enabled else 0),
        ("UI_PORT", cfg.ui_port),
        ("DNS_PORT", cfg.dns_port),
        ("DEFAULT_POLICY", cfg.default_policy),
        # Consumed by `gw client` and the dashboard so both offer exactly the
        # policies this config defines.
        ("POLICIES", ",".join(cfg.policies)),
        ("PROFILES", ",".join(cfg.profiles)),
    ]
    lines = ["# Generated by `gw apply` — consumed by the gateway helper scripts",
             "# Values are quoted; source this file, do not grep it."]
    for key, value in pairs:
        text = str(value)
        if '"' in text or "\\" in text:
            raise RuntimeError(f"{key} contains a quote or backslash: {text!r}")
        lines.append(f'{key}="{text}"')
    return "\n".join(lines) + "\n"


def target_wants(cfg: Config) -> str:
    """Third-party units the gateway stack pulls in at boot."""
    lines = ["Wants=AdGuardHome.service", "After=AdGuardHome.service"]
    if cfg.web_enabled:
        lines.append("Wants=gw-web.service")
    if cfg.ts_enabled:
        # Wanted, but deliberately NOT PartOf the target: a restart of the
        # stack must not drop the Tailscale session you are managing it over.
        lines.append("Wants=tailscaled.service")
    return "\n".join(lines) + "\n"


def render_jobs(cfg: Config) -> dict[str, str]:
    """Scheduled jobs as a cron table plus one script per job.

    The script bodies live in their own files rather than inline in the crontab
    because cron treats % as a newline and gives no error for a malformed line
    — it just never runs. A one-line `run this script` entry keeps the crontab
    trivially correct and leaves the bash where it can be read and tested.
    """
    files: dict[str, str] = {}
    lines = [
        "# Generated by `gw apply` — DO NOT EDIT ON THE BOX.",
        "# Edit [[job]] entries in gateway.toml, or use `gw job` / the dashboard.",
        "SHELL=/bin/bash",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "",
    ]

    for job in cfg.jobs:
        path = f"usr/local/lib/gateway/jobs/{job['name']}.sh"
        header = [
            "#!/bin/bash",
            f"# {job['name']}"
            + (f" — {job['description']}" if job["description"] else ""),
            "#",
            "# Generated by `gw apply` from [[job]] in gateway.toml.",
            f"# Schedule: {job['schedule']}   User: {job['user']}",
            "set -euo pipefail",
            "",
        ]
        files[path] = "\n".join(header) + job["script"].rstrip("\n") + "\n"

        if not job["enabled"]:
            lines.append(f"# disabled: {job['name']}")
            continue
        if job["description"]:
            lines.append(f"# {job['description']}")
        # Output is captured by cron and mailed nowhere on a box with no MTA,
        # so send it to the journal where `gw logs` can find it.
        lines.append(
            f"{job['schedule']}\t{job['user']}\t"
            f"/usr/local/lib/gateway/jobs/{job['name']}.sh "
            f"2>&1 | logger -t gw-job-{job['name']}"
        )

    lines.append("")
    files["etc/cron.d/gw-jobs"] = "\n".join(lines)
    return files


def render_tailscale_args(cfg: Config) -> str:
    if not cfg.ts_enabled:
        return "# tailscale.enabled = false\n"
    args = ["--accept-dns=false", "--accept-routes=false"]
    if cfg.ts_ssh:
        args.append("--ssh")
    if cfg.ts_exit_node:
        args.append("--advertise-exit-node")
    if cfg.ts_subnet_router:
        args.append(f"--advertise-routes={cfg.lan_cidr}")
    return " ".join(args) + "\n"


def render(cfg: Config, out: pathlib.Path) -> list[str]:
    if out.exists():
        shutil.rmtree(out)

    files: dict[str, str] = {
        "etc/nftables.d/gateway.nft": render_nft(cfg),
        "etc/sysctl.d/99-gateway.conf": render_sysctl(cfg),
        "etc/systemd/network/10-gateway-wan.network": render_network(cfg),
        "usr/local/etc/xray/config.json": xray_config.render(cfg),
        "usr/local/lib/gateway/env": render_env(cfg),
    }

    for name in ("ip-rules.sh", "health.sh", "geoupdate.sh", "ts-bypass.sh",
                 "net.sh", "xray-update.sh", "adguard-update.sh"):
        files[f"usr/local/lib/gateway/{name}"] = (TPL / "lib" / name).read_text()

    files.update(render_jobs(cfg))

    if cfg.web_enabled:
        files["usr/local/lib/gateway/web-action.py"] = (
            TPL / "lib" / "web-action.py"
        ).read_text()
        # Deliberately contains no secrets: the password hash lives in
        # /etc/gateway/web-auth.json, 0600 root:root, and is never rendered.
        files["etc/gateway/web.json"] = json.dumps(
            {
                "listen": cfg.web_listen,
                "port": cfg.web_port,
                "tls": cfg.web_tls,
                "cert": cfg.web_cert,
                "key": cfg.web_key,
                "allow_cidrs": cfg.web_allow,
                "session_hours": cfg.session_hours,
                "max_failed_logins": cfg.max_failed_logins,
                "lockout_minutes": cfg.lockout_minutes,
            },
            indent=2,
        ) + "\n"
        files["etc/sudoers.d/gw-web"] = (TPL / "sudoers.gw-web").read_text()
        for asset in sorted((TPL / "web").iterdir()):
            files[f"usr/local/share/gateway/web/{asset.name}"] = asset.read_text()

    for unit in sorted((TPL / "systemd").iterdir()):
        if unit.name == "gw-tailscale-exception.service" and (
            cfg.ts_route_control or not cfg.ts_enabled
        ):
            continue
        if unit.name == "gw-web.service" and not cfg.web_enabled:
            continue
        text = unit.read_text()
        if "{{" in text:
            text = subst(
                text,
                {
                    "HEALTH_INTERVAL": str(cfg.health_interval),
                    "TARGET_WANTS": target_wants(cfg),
                    "REPO": str(ROOT),
                },
            )
        files[f"etc/systemd/system/{unit.name}"] = text

    # AdGuard installs its own unit, so it is extended rather than replaced.
    files["etc/systemd/system/AdGuardHome.service.d/gw.conf"] = (
        TPL / "systemd-dropin" / "adguard-gw.conf"
    ).read_text()

    if cfg.ts_enabled and not cfg.ts_route_control:
        files["etc/systemd/system/tailscaled.service.d/gw-exception.conf"] = (
            TPL / "systemd-dropin" / "tailscaled-gw-exception.conf"
        ).read_text()

    written = []
    for rel, content in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        if rel.startswith("usr/local/lib/gateway/jobs/"):
            # Job scripts run as root and may hold credentials.
            mode = 0o700
        elif rel in EXECUTABLE:
            mode = 0o755
        else:
            mode = 0o644
        path.chmod(mode)
        written.append(rel)

    # Not filesystem-shaped: consumed by `gw apply` at install time.
    (out / "adguard-overrides.json").write_text(
        json.dumps(adguard.overrides(cfg), indent=2) + "\n"
    )
    (out / "tailscale-args").write_text(render_tailscale_args(cfg))
    return written


def main() -> int:
    cfg_path = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "gateway.toml")
    out = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "build"
    try:
        cfg = gwconfig.load(cfg_path)
    except gwconfig.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 1
    written = render(cfg, out)
    for rel in written:
        print(f"  {rel}")
    print(f"rendered {len(written)} files into {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
