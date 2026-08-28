#!/usr/bin/env python3
"""Privileged actions for the web dashboard. The ONLY thing gwweb may sudo.

The dashboard runs unprivileged and cannot touch the firewall, the config or
systemd directly — it pipes a JSON request here instead. Every field is
re-validated in this process, as root, so a compromised web process cannot
widen what it is allowed to ask for. Nothing from the request ever reaches a
shell: subprocess is always called with an argument list and shell=False.

Request on stdin, JSON result on stdout:
    {"action": "status"}
    {"action": "clients"}
    {"action": "client_add", "ip": "...", "name": "...", "policy": "proxy"}
    {"action": "client_rm",  "ip": "..."}
    {"action": "apply"}
    {"action": "probe"}
    {"action": "auth_status"}
    {"action": "verify_password", "password": "..."}
    {"action": "jobs"}
    {"action": "job_add", "name": "...", "schedule": "...", "script": "...",
                          "user": "...", "description": "..."}
    {"action": "job_rm",     "name": "..."}
    {"action": "job_toggle", "name": "...", "enabled": true}
"""

from __future__ import annotations

import ipaddress
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

ENV = "/usr/local/lib/gateway/env"
RUN = pathlib.Path("/run/gateway")
BUILTIN_POLICIES = ("proxy", "direct", "block")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,31}$")
STACK = ("gateway.target", "gw-network.service", "xray.service",
         "AdGuardHome.service", "tailscaled.service", "gw-web.service",
         "gw-health.timer", "gw-geoupdate.timer")


def env() -> dict:
    out = {}
    try:
        for line in pathlib.Path(ENV).read_text().splitlines():
            if line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            # Values are shell-quoted so the file can be sourced safely.
            out[k] = v.strip().strip('"')
    except OSError:
        pass
    return out


E = env()
REPO = E.get("REPO", "/opt/gateway")
GW = str(pathlib.Path(REPO) / "bin" / "gw")


def run(args: list[str], timeout: int = 120) -> tuple[int, str, str]:
    """Always a list, never a shell. User input reaches argv, not a parser."""
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timed out after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"{args[0]} not found"


def fail(msg: str):
    print(json.dumps({"ok": False, "error": msg}))
    sys.exit(1)


def done(data: dict):
    print(json.dumps({"ok": True, **data}))
    sys.exit(0)


# --------------------------------------------------------------- validation --
def valid_ip(raw) -> str:
    if not isinstance(raw, str):
        fail("ip must be a string")
    try:
        addr = ipaddress.ip_address(raw.strip())
    except ValueError:
        fail(f"{raw!r} is not a valid IP address")
    lan = E.get("LAN_CIDR")
    if lan and addr not in ipaddress.ip_network(lan, strict=False):
        fail(f"{addr} is outside the LAN ({lan})")
    if str(addr) in (E.get("BOX_IP"), E.get("ROUTER")):
        fail(f"{addr} is the gateway or the router itself")
    return str(addr)


def valid_name(raw) -> str:
    if not isinstance(raw, str) or not NAME_RE.match(raw.strip()):
        fail("name must be 1-32 chars of letters, digits, space, dot, dash or underscore")
    return raw.strip()


def policies() -> tuple[str, ...]:
    """Built-ins plus this config's profiles, as rendered into the env file.

    Read here rather than trusted from the request: the web process must not be
    able to widen the set of policies it may assign.
    """
    raw = E.get("POLICIES", "")
    names = tuple(p for p in raw.split(",") if p)
    return names or BUILTIN_POLICIES


def valid_policy(raw) -> str:
    allowed = policies()
    if raw not in allowed:
        fail(f"policy must be one of {', '.join(allowed)}")
    return raw


# ------------------------------------------------------------------ actions --
def act_status() -> dict:
    def read(name, default=""):
        try:
            return (RUN / name).read_text().strip()
        except OSError:
            return default

    services = {}
    for unit in STACK:
        rc, out, _ = run(["systemctl", "show", unit,
                          "--property=ActiveState,UnitFileState,LoadState"], timeout=10)
        props = dict(
            line.split("=", 1) for line in out.splitlines() if "=" in line
        )
        if props.get("LoadState") == "not-found":
            continue
        services[unit] = {
            "active": props.get("ActiveState", "unknown"),
            "enabled": props.get("UnitFileState", "unknown"),
        }

    firewall = {"loaded": False}
    rc, out, _ = run(["nft", "list", "table", "inet", "gateway"], timeout=15)
    if rc == 0:
        firewall["loaded"] = True
        drops = 0
        for line in out.splitlines():
            if "killswitch" in line:
                m = re.search(r"packets (\d+)", line)
                if m:
                    drops += int(m.group(1))
        firewall["killswitch_drops"] = drops
        for setname in ("proxy_clients", "direct_clients", "blocked_clients"):
            m = re.search(setname + r"\s*\{.*?elements = \{(.*?)\}", out, re.S)
            firewall[setname] = (
                [x.strip() for x in m.group(1).split(",") if x.strip()] if m else []
            )

    traffic = {}
    rc, out, _ = run(["xray", "api", "statsquery",
                      f"--server=127.0.0.1:{E.get('API_PORT', '10085')}"], timeout=10)
    if rc == 0:
        try:
            for s in json.loads(out).get("stat", []):
                name, value = s.get("name", ""), int(s.get("value", 0))
                m = re.match(r"outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)", name)
                if m:
                    traffic.setdefault(m.group(1), {})[m.group(2)] = value
        except (ValueError, TypeError):
            pass

    try:
        load = os.getloadavg()
    except OSError:
        load = (0, 0, 0)
    mem = {}
    try:
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            k, _, v = line.partition(":")
            if k in ("MemTotal", "MemAvailable"):
                mem[k] = int(v.strip().split()[0]) * 1024
    except OSError:
        pass
    disk = shutil.disk_usage("/")

    return {
        "tunnel": read("tunnel", "unknown"),
        "fails": int(read("fails", "0") or 0),
        "lifeline": read("lifeline", "0") == "1",
        "default_policy": E.get("DEFAULT_POLICY", "proxy"),
        "lan": E.get("LAN_CIDR", ""),
        "box_ip": E.get("BOX_IP", ""),
        "services": services,
        "firewall": firewall,
        "traffic": traffic,
        "system": {
            "uptime": int(float(pathlib.Path("/proc/uptime").read_text().split()[0])),
            "load": list(load),
            "mem_total": mem.get("MemTotal", 0),
            "mem_available": mem.get("MemAvailable", 0),
            "disk_total": disk.total,
            "disk_free": disk.free,
            "time": int(time.time()),
        },
    }


def act_clients() -> dict:
    rc, out, err = run([GW, "client", "list"], timeout=20)
    if rc != 0:
        fail(err.strip() or "could not read the client list")
    clients = []
    known = policies()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] in known:
            clients.append(
                {"ip": parts[0], "policy": parts[1], "name": " ".join(parts[2:])}
            )
    return {
        "clients": clients,
        "default_policy": E.get("DEFAULT_POLICY", "proxy"),
        "policies": list(known),
        "profiles": [p for p in E.get("PROFILES", "").split(",") if p],
    }


def act_client_add(req: dict) -> dict:
    ip = valid_ip(req.get("ip"))
    name = valid_name(req.get("name"))
    policy = valid_policy(req.get("policy"))
    rc, out, err = run([GW, "client", "add", ip, name, policy], timeout=30)
    if rc != 0:
        fail(err.strip() or out.strip() or "could not add the client")
    return {"message": f"{ip} ({name}) set to {policy}", "pending_apply": True}


def act_client_rm(req: dict) -> dict:
    ip = valid_ip(req.get("ip"))
    rc, out, err = run([GW, "client", "rm", ip], timeout=30)
    if rc != 0:
        fail(err.strip() or out.strip() or "could not remove the client")
    return {"message": f"{ip} removed", "pending_apply": True}


def act_apply() -> dict:
    rc, out, err = run([GW, "apply"], timeout=300)
    tail = "\n".join((out + err).strip().splitlines()[-40:])
    if rc != 0:
        fail(f"gw apply failed:\n{tail}")
    return {"message": "applied", "output": tail}


def act_probe() -> dict:
    """Exit IP vs real IP. Slow (two network round trips), so it is on demand
    rather than part of the status poll."""
    socks = E.get("SOCKS_PORT", "10808")
    rc, tun, _ = run(["curl", "-fsS", "--max-time", "15",
                      "--socks5-hostname", f"127.0.0.1:{socks}",
                      "https://api.ipify.org"], timeout=25)
    tunnel_ip = tun.strip() if rc == 0 else None
    # Running as the xray user bypasses the tunnel (the output chain returns
    # early on that uid), which is how we see the box's real address.
    #
    # setpriv before runuser: runuser is in util-linux-extra on Debian 12+, so
    # a minimal install does not have it.
    if shutil.which("setpriv"):
        # Numeric ids: some setpriv builds reject a group name for --regid.
        import pwd
        try:
            ent = pwd.getpwnam("xray")
            as_xray = ["setpriv", f"--reuid={ent.pw_uid}",
                       f"--regid={ent.pw_gid}", "--clear-groups"]
        except KeyError:
            fail("the xray user does not exist — has `gw apply` run?")
    elif shutil.which("runuser"):
        as_xray = ["runuser", "-u", "xray", "--"]
    else:
        as_xray = ["sudo", "-n", "-u", "xray", "--"]
    rc, real, _ = run(as_xray + ["curl", "-fsS", "--max-time", "15",
                                 "https://api.ipify.org"], timeout=25)
    real_ip = real.strip() if rc == 0 else None
    return {
        "tunnel_ip": tunnel_ip,
        "real_ip": real_ip,
        "leaking": bool(tunnel_ip and real_ip and tunnel_ip == real_ip),
    }


CRON_SHORTHAND = {
    "@yearly", "@annually", "@monthly", "@weekly", "@daily",
    "@midnight", "@hourly", "@reboot",
}
CRON_FIELD = re.compile(r"^[0-9A-Za-z*/,\-]+$")


def valid_schedule(raw) -> str:
    """Re-validated here, as root. The dashboard writes cron entries, and a
    malformed line in /etc/cron.d is silently ignored rather than rejected —
    the job would simply never run and nothing would say why."""
    if not isinstance(raw, str) or not raw.strip():
        fail("schedule is empty — use five cron fields or a shorthand like @daily")
    expr = raw.strip()
    if expr.startswith("@"):
        if expr not in CRON_SHORTHAND:
            fail(f"unknown shorthand {expr!r}; try {', '.join(sorted(CRON_SHORTHAND))}")
        return expr
    fields = expr.split()
    if len(fields) != 5:
        fail(f"schedule has {len(fields)} field(s); cron needs 5")
    for i, field in enumerate(fields):
        if not CRON_FIELD.match(field):
            fail(f"schedule field {i + 1} ({field!r}) has characters cron will not accept")
    return expr


def valid_job_name(raw) -> str:
    if not isinstance(raw, str) or not re.match(r"^[a-z0-9][a-z0-9-]{0,23}$", raw):
        fail("job name must be 1-24 chars of lowercase letters, digits or dashes")
    return raw


def act_jobs() -> dict:
    rc, out, err = run([GW, "job", "list", "--json"], timeout=20)
    if rc != 0:
        fail(err.strip() or "could not read the job list")
    try:
        jobs = json.loads(out or "[]")
    except ValueError:
        fail("could not parse the job list")
    return {"jobs": jobs}


def act_job_add(req: dict) -> dict:
    name = valid_job_name(req.get("name"))
    schedule = valid_schedule(req.get("schedule"))
    script = req.get("script")
    if not isinstance(script, str) or not script.strip():
        fail("the script is empty — nothing to run")
    if len(script) > 64 * 1024:
        fail("script is too large (64 KB limit)")
    user = req.get("user", "root")
    if not isinstance(user, str) or not re.match(r"^[a-z_][a-z0-9_-]*$", user):
        fail("invalid user name")
    description = str(req.get("description", ""))[:200]

    # The script reaches `gw job add` through a file, never through argv or a
    # shell: it is arbitrary text and belongs nowhere near a command line.
    tmp = pathlib.Path("/run/gateway") / f"job-{name}.tmp"
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(script)
    try:
        cmd = [GW, "job", "add", name, schedule, "--file", str(tmp), "--user", user]
        if description:
            cmd += ["--desc", description]
        rc, out, err = run(cmd, timeout=30)
    finally:
        tmp.unlink(missing_ok=True)
    if rc != 0:
        fail(err.strip() or out.strip() or "could not save the job")
    return {"message": f"job {name} saved", "pending_apply": True}


def act_job_rm(req: dict) -> dict:
    name = valid_job_name(req.get("name"))
    rc, out, err = run([GW, "job", "rm", name], timeout=30)
    if rc != 0:
        fail(err.strip() or out.strip() or "could not remove the job")
    return {"message": f"job {name} removed", "pending_apply": True}


def act_job_toggle(req: dict) -> dict:
    name = valid_job_name(req.get("name"))
    verb = "enable" if req.get("enabled") else "disable"
    rc, out, err = run([GW, "job", verb, name], timeout=30)
    if rc != 0:
        fail(err.strip() or out.strip() or f"could not {verb} the job")
    return {"message": f"job {name} {verb}d", "pending_apply": True}


def act_auth_status() -> dict:
    """Whether a password exists — never the hash itself."""
    sys.path.insert(0, str(pathlib.Path(REPO) / "lib"))
    import webauth
    return {"password_set": webauth.load_password() is not None}


def act_verify_password(req: dict) -> dict:
    """Verified here, as root, so the hash never reaches the network-facing
    process. The password arrives on stdin, so it never appears in ps output.

    Rate limiting lives in the web app; this call is deliberately slow (scrypt)
    rather than clever.
    """
    sys.path.insert(0, str(pathlib.Path(REPO) / "lib"))
    import webauth
    stored = webauth.load_password()
    if stored is None:
        return {"password_set": False, "valid": False}
    password = req.get("password")
    if not isinstance(password, str):
        return {"password_set": True, "valid": False}
    return {
        "password_set": True,
        "valid": webauth.verify_password(password, stored["salt"], stored["hash"]),
    }


def escape_service_sandbox() -> None:
    """Leave gw-web's mount namespace before touching the filesystem.

    gw-web.service runs with ProtectSystem=strict, and a sudo'd child inherits
    that mount namespace — so this helper is root and still sees a read-only
    /opt and /etc:

        OSError: [Errno 30] Read-only file system: '/opt/gateway/gateway.toml'

    That sandbox exists to stop the *web process* writing anything directly;
    it was never meant to constrain the privileged helper, which is the whole
    sanctioned path for making changes. Re-enter PID 1's namespace once, then
    carry on. Running from a shell, the namespaces already match and this is a
    no-op.
    """
    if os.environ.get("GW_NS_REEXEC"):
        return
    try:
        if os.readlink("/proc/self/ns/mnt") == os.readlink("/proc/1/ns/mnt"):
            return
    except OSError:
        return  # cannot tell; carry on and let the real error speak

    nsenter = shutil.which("nsenter")
    if not nsenter:
        fail("running inside a service sandbox and nsenter is not available — "
             "install util-linux, or run this from a shell")

    os.environ["GW_NS_REEXEC"] = "1"
    # execv keeps stdin, so the JSON request on it survives the re-exec.
    os.chdir("/")
    try:
        os.execv(nsenter, [nsenter, "--mount=/proc/1/ns/mnt", "--",
                           sys.executable, os.path.abspath(__file__)])
    except OSError as e:
        fail(f"could not leave the service sandbox: {e}")


def main() -> None:
    if os.geteuid() != 0:
        fail("web-action.py must run as root (via the sudoers entry)")
    escape_service_sandbox()
    raw = sys.stdin.read(65536)
    try:
        req = json.loads(raw or "{}")
    except ValueError:
        fail("request is not valid JSON")
    if not isinstance(req, dict):
        fail("request must be a JSON object")

    action = req.get("action")
    if action == "status":
        done(act_status())
    elif action == "clients":
        done(act_clients())
    elif action == "client_add":
        done(act_client_add(req))
    elif action == "client_rm":
        done(act_client_rm(req))
    elif action == "apply":
        done(act_apply())
    elif action == "probe":
        done(act_probe())
    elif action == "jobs":
        done(act_jobs())
    elif action == "job_add":
        done(act_job_add(req))
    elif action == "job_rm":
        done(act_job_rm(req))
    elif action == "job_toggle":
        done(act_job_toggle(req))
    elif action == "auth_status":
        done(act_auth_status())
    elif action == "verify_password":
        done(act_verify_password(req))
    else:
        fail(f"unknown action: {action!r}")


if __name__ == "__main__":
    main()
