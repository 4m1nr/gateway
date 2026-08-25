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
    if cfg.default_policy == "proxy":
        pre_default = (
            "        meta l4proto { tcp, udp } ip saddr $LAN \\\n"
            "            meta mark set $MARK_TPROXY "
            "tproxy ip to 127.0.0.1:$TPROXY_PORT accept\n"
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
            "ELEM_DIRECT": nft_elements(cfg.clients_by("direct")),
            "ELEM_BLOCKED": nft_elements(cfg.clients_by("block")),
            "ELEM_BYPASS": nft_elements(cfg.bypass_dst),
            "ELEM_EXCEPTIONS": exceptions,
            "IPV6_PREROUTING": v6_pre,
            "IPV6_OUTPUT": v6_out,
            "IPV6_FORWARD": v6_fwd,
            "PREROUTING_DEFAULT": pre_default,
            "FORWARD_DEFAULT": fwd_default,
            "POSTROUTING_DEFAULT": post_default,
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
    return "\n".join(
        [
            "# Generated by `gw apply` — consumed by the gateway helper scripts",
            f"REPO={ROOT}",
            f"WAN_IF={cfg.wan_if}",
            f"LAN_CIDR={cfg.lan_cidr}",
            f"BOX_IP={cfg.box_ip}",
            f"ROUTER={cfg.router}",
            f"TPROXY_PORT={cfg.tproxy_port}",
            f"SOCKS_PORT={cfg.socks_port}",
            f"HTTP_PORT={cfg.http_port}",
            f"API_PORT={cfg.api_port}",
            "MARK_TPROXY=1",
            f"MARK_XRAY={cfg.outbound_mark}",
            f"RT_TABLE={RT_TABLE}",
            f"PROBE_URL={cfg.probe_url}",
            f"PROBE_TIMEOUT={cfg.probe_timeout}",
            f"DOMESTIC_PROBE_URL={cfg.domestic_probe_url}",
            f"INTERVAL={cfg.health_interval}",
            f"RESTART_AFTER={cfg.restart_after}",
            f"FALLBACK_AFTER={cfg.fallback_after}",
            f"LIFELINE_MIN={cfg.ts_lifeline_min if cfg.ts_enabled else 0}",
            f"UI_PORT={cfg.ui_port}",
            f"DNS_PORT={cfg.dns_port}",
            f"DEFAULT_POLICY={cfg.default_policy}",
            "",
        ]
    )


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

    for name in ("ip-rules.sh", "health.sh", "geoupdate.sh", "ts-bypass.sh"):
        files[f"usr/local/lib/gateway/{name}"] = (TPL / "lib" / name).read_text()

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
        path.chmod(0o755 if rel in EXECUTABLE else 0o644)
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
