"""`gw client` — per-client policy, edited in place in gateway.toml.

Appends and removes whole [[client]] blocks textually so comments and
formatting elsewhere in the file survive; tomllib can read TOML but not write
it, and pulling in a writer library would break the no-dependencies rule.
"""

from __future__ import annotations

import ipaddress
import pathlib
import re
import sys
import tomllib

BUILTIN = ("proxy", "direct", "block")


def valid_policies(path: pathlib.Path) -> tuple[str, ...]:
    """Built-ins plus whatever profiles this config defines."""
    try:
        with path.open("rb") as fh:
            raw = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return BUILTIN
    names = [p["name"] for p in raw.get("profile", []) if isinstance(p, dict) and "name" in p]
    return BUILTIN + tuple(names)
BLOCK = re.compile(
    r'\n?\[\[client\]\]\nip     = "(?P<ip>[^"]+)"\nname   = "(?P<name>[^"]*)"\n'
    # [\w-] not \w: profile names may contain hyphens, and \w silently fails to
    # match them — which made profile clients invisible to list/rm and caused
    # add to duplicate instead of replace.
    r'policy = "(?P<policy>[\w-]+)"\n'
)


def read(path: pathlib.Path) -> str:
    if not path.exists():
        sys.exit(f"{path} not found — run `gw init` first")
    return path.read_text()


def cmd_list(path: pathlib.Path) -> int:
    text = read(path)
    rows = [(m["ip"], m["name"], m["policy"]) for m in BLOCK.finditer(text)]
    profiles = [p for p in valid_policies(path) if p not in BUILTIN]
    if profiles:
        print(f"# profiles available: {', '.join(profiles)}\n")
    if not rows:
        print("no overrides configured — every device using this box as its "
              "gateway gets [policy].default")
        return 0
    ipw = max(len(r[0]) for r in rows)
    polw = max(len(r[2]) for r in rows)
    for ip, name, policy in sorted(rows, key=lambda r: ipaddress.ip_address(r[0])):
        print(f"{ip:<{ipw}}  {policy:<{polw}}  {name}")
    return 0


def cmd_add(path: pathlib.Path, ip: str, name: str, policy: str) -> int:
    ipaddress.ip_address(ip)
    allowed = valid_policies(path)
    if policy not in allowed:
        sys.exit(
            f"policy {policy!r} is not defined. Known policies: {', '.join(allowed)}\n"
            "Profiles are declared with [[profile]] in gateway.toml."
        )
    text = read(path)
    for m in BLOCK.finditer(text):
        if m["ip"] == ip:
            text = text[: m.start()] + text[m.end():]
            print(f"replacing existing entry for {ip} ({m['policy']} -> {policy})")
            break
    text = text.rstrip("\n") + (
        f'\n\n[[client]]\nip     = "{ip}"\nname   = "{name}"\npolicy = "{policy}"\n'
    )
    path.write_text(text)
    print(f"{ip} ({name}) -> {policy}")
    print("run `sudo gw apply` to make it live")
    return 0


def cmd_rm(path: pathlib.Path, ip: str) -> int:
    text = read(path)
    for m in BLOCK.finditer(text):
        if m["ip"] == ip:
            path.write_text(text[: m.start()] + text[m.end():])
            print(f"removed {ip}; run `sudo gw apply` to make it live")
            return 0
    sys.exit(f"{ip} is not in {path}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.exit("usage: gw client <list|add|rm> ...")
    path = pathlib.Path(argv[0])
    cmd, rest = argv[1], argv[2:]
    if cmd == "list":
        return cmd_list(path)
    if cmd == "add":
        if len(rest) < 2:
            allowed = " | ".join(valid_policies(path))
            sys.exit(f"usage: gw client add <ip> <name> [{allowed}]")
        return cmd_add(path, rest[0], rest[1], rest[2] if len(rest) > 2 else "proxy")
    if cmd == "rm":
        if len(rest) != 1:
            sys.exit("usage: gw client rm <ip>")
        return cmd_rm(path, rest[0])
    sys.exit(f"unknown subcommand: {cmd}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
