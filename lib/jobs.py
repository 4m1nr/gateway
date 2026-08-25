"""`gw job` — scheduled jobs, edited in gateway.toml.

Jobs are read from anywhere in the file, but the ones this tool writes live in
a marked region it rewrites wholesale. Textual surgery on a multi-line script
block is how you end up with a half-deleted heredoc in your config; regenerating
a machine-managed region is boring and safe, and it leaves hand-written jobs
elsewhere in the file alone.

Scripts are stored as TOML *literal* multi-line strings, the single-quoted
kind. The double-quoted kind processes escapes, so a bash line continuation
would be collapsed and a backslash-n would become a real newline — quietly
rewriting the script between what you wrote and what actually runs.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
import tomllib

BEGIN = "# >>> gw job entries — managed by `gw job` and the dashboard >>>"
END = "# <<< gw job entries <<<"
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")


def read(path: pathlib.Path) -> str:
    if not path.exists():
        sys.exit(f"{path} not found — run `gw init` first")
    return path.read_text()


def parse(path: pathlib.Path) -> list[dict]:
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh).get("job", [])
    except (OSError, tomllib.TOMLDecodeError) as e:
        sys.exit(f"{path}: {e}")


def managed_region(text: str) -> tuple[int, int] | None:
    a, b = text.find(BEGIN), text.find(END)
    if a < 0 or b < 0 or b < a:
        return None
    return a, b + len(END)


def serialise(job: dict) -> str:
    script = job["script"].rstrip("\n")
    if "'''" in script:
        sys.exit(
            f"job {job['name']}: the script contains ''' , which terminates a "
            "TOML literal string. Remove it or edit gateway.toml by hand."
        )
    out = [
        "[[job]]",
        f'name        = "{job["name"]}"',
        f'schedule    = "{job["schedule"]}"',
        f'user        = "{job.get("user", "root")}"',
        f'enabled     = {"true" if job.get("enabled", True) else "false"}',
    ]
    if job.get("description"):
        desc = job["description"].replace('"', "'")
        out.append(f'description = "{desc}"')
    out.append("script      = '''")
    out.append(script)
    out.append("'''")
    return "\n".join(out)


def write_jobs(path: pathlib.Path, jobs: list[dict]) -> None:
    body = "\n\n".join(serialise(j) for j in jobs)
    block = f"{BEGIN}\n{body}\n{END}\n" if jobs else f"{BEGIN}\n{END}\n"

    text = read(path)
    region = managed_region(text)
    if region:
        text = text[: region[0]] + block.rstrip("\n") + text[region[1]:]
    else:
        text = text.rstrip("\n") + "\n\n" + block
    path.write_text(text)


def managed_jobs(path: pathlib.Path) -> list[dict]:
    """Jobs inside the managed region. Anything outside it is hand-written and
    left alone — but it still runs, so it is shown with a marker."""
    text = read(path)
    region = managed_region(text)
    if not region:
        return []
    fragment = text[region[0]: region[1]]
    try:
        return tomllib.loads(fragment.replace(BEGIN, "").replace(END, "")).get("job", [])
    except tomllib.TOMLDecodeError:
        return []


def cmd_list(path: pathlib.Path, as_json: bool = False) -> int:
    all_jobs = parse(path)
    managed_names = {j["name"] for j in managed_jobs(path)}
    if as_json:
        # The dashboard consumes this. Parsing the human table would break the
        # moment a description contained a space.
        print(json.dumps([{
            "name": j.get("name", ""),
            "schedule": j.get("schedule", ""),
            "user": j.get("user", "root"),
            "enabled": bool(j.get("enabled", True)),
            "description": j.get("description", ""),
            "script": j.get("script", ""),
            "managed": j.get("name") in managed_names,
        } for j in all_jobs]))
        return 0
    if not all_jobs:
        print("no scheduled jobs")
        return 0
    width = max(len(j.get("name", "")) for j in all_jobs)
    for j in all_jobs:
        state = "  " if j.get("enabled", True) else "off"
        where = "" if j["name"] in managed_names else "  (hand-written)"
        first = j.get("script", "").strip().splitlines()[:1]
        print(f"{j['name']:<{width}}  {state}  {j.get('schedule', ''):<14} "
              f"{j.get('user', 'root'):<8} {j.get('description') or (first[0] if first else '')}"
              f"{where}")
    return 0


def cmd_add(path: pathlib.Path, name: str, schedule: str, script: str,
            user: str = "root", description: str = "") -> int:
    if not NAME_RE.match(name):
        sys.exit("job name must be 1-24 chars of lowercase letters, digits or dashes")
    if not script.strip():
        sys.exit("the script is empty — nothing to run")

    jobs = [dict(j) for j in managed_jobs(path)]
    for j in jobs:
        if j["name"] == name:
            jobs.remove(j)
            print(f"replacing the existing job {name!r}")
            break
    hand = [j["name"] for j in parse(path)] 
    if name in hand and name not in [j["name"] for j in managed_jobs(path)]:
        sys.exit(
            f"a hand-written job named {name!r} already exists in {path}. "
            "Rename one of them, or edit that entry directly."
        )

    jobs.append({
        "name": name, "schedule": schedule, "script": script,
        "user": user, "enabled": True, "description": description,
    })
    write_jobs(path, jobs)
    print(f"job {name!r} scheduled: {schedule} (as {user})")
    print("run `sudo gw apply` to install it")
    return 0


def cmd_rm(path: pathlib.Path, name: str) -> int:
    jobs = [dict(j) for j in managed_jobs(path)]
    remaining = [j for j in jobs if j["name"] != name]
    if len(remaining) == len(jobs):
        if any(j.get("name") == name for j in parse(path)):
            sys.exit(f"{name!r} is a hand-written job — remove it from {path} yourself")
        sys.exit(f"no job named {name!r}")
    write_jobs(path, remaining)
    print(f"removed {name!r}; run `sudo gw apply` to make it live")
    return 0


def cmd_toggle(path: pathlib.Path, name: str, enabled: bool) -> int:
    jobs = [dict(j) for j in managed_jobs(path)]
    for j in jobs:
        if j["name"] == name:
            j["enabled"] = enabled
            write_jobs(path, jobs)
            print(f"{name!r} {'enabled' if enabled else 'disabled'}; "
                  "run `sudo gw apply` to make it live")
            return 0
    sys.exit(f"no managed job named {name!r}")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.exit("usage: gw job <list|add|rm|enable|disable> ...")
    path = pathlib.Path(argv[0])
    cmd, rest = argv[1], argv[2:]

    if cmd == "list":
        return cmd_list(path, as_json="--json" in rest)
    if cmd == "add":
        if len(rest) < 2:
            sys.exit(
                "usage: gw job add <name> <schedule> [--user U] [--desc D] "
                "[--file script.sh | -]\n"
                '  e.g. gw job add nightly "0 4 * * *" --file backup.sh\n'
                "       echo 'reboot' | gw job add weekly-reboot @weekly -"
            )
        name, schedule = rest[0], rest[1]
        opts, source = rest[2:], None
        user, desc = "root", ""
        i = 0
        while i < len(opts):
            if opts[i] == "--user":
                user = opts[i + 1]; i += 2
            elif opts[i] == "--desc":
                desc = opts[i + 1]; i += 2
            elif opts[i] == "--file":
                source = opts[i + 1]; i += 2
            elif opts[i] == "-":
                source = "-"; i += 1
            else:
                sys.exit(f"unknown option: {opts[i]}")
        if source == "-" or source is None:
            script = sys.stdin.read()
        else:
            try:
                script = pathlib.Path(source).read_text()
            except OSError as e:
                sys.exit(f"--file: {e}")
        return cmd_add(path, name, schedule, script, user, desc)
    if cmd == "rm":
        if len(rest) != 1:
            sys.exit("usage: gw job rm <name>")
        return cmd_rm(path, rest[0])
    if cmd in ("enable", "disable"):
        if len(rest) != 1:
            sys.exit(f"usage: gw job {cmd} <name>")
        return cmd_toggle(path, rest[0], cmd == "enable")
    sys.exit(f"unknown subcommand: {cmd}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
