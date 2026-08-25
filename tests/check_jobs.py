"""Assert every scheduled job is actually installable.

A job that renders a script but no crontab line (or the reverse) is a job that
silently never runs. cron gives no error for a missing or malformed entry, so
this is the only place it gets noticed.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, "lib")
import gwconfig  # noqa: E402


def main(toml_path: str, build_dir: str) -> int:
    cfg = gwconfig.load(toml_path)
    build = pathlib.Path(build_dir)
    crontab = (build / "etc/cron.d/gw-jobs").read_text()
    problems = []

    for job in cfg.jobs:
        script = build / f"usr/local/lib/gateway/jobs/{job['name']}.sh"
        if not script.exists():
            problems.append(f"{job['name']}: no script rendered")
            continue
        body = script.read_text()
        if not body.startswith("#!/bin/bash"):
            problems.append(f"{job['name']}: script has no shebang")
        if job["script"].strip().splitlines()[0] not in body:
            problems.append(f"{job['name']}: script body was not preserved")

        line = [
            ln for ln in crontab.splitlines()
            if f"/jobs/{job['name']}.sh" in ln and not ln.lstrip().startswith("#")
        ]
        if job["enabled"] and not line:
            problems.append(f"{job['name']}: enabled but has no crontab line")
        if not job["enabled"] and line:
            problems.append(f"{job['name']}: disabled but still has a crontab line")
        if line:
            fields = line[0].split("\t")
            if len(fields) < 3:
                problems.append(f"{job['name']}: crontab line is malformed")
            elif fields[1] != job["user"]:
                problems.append(
                    f"{job['name']}: crontab runs as {fields[1]}, expected {job['user']}"
                )

    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print(f"ok: {len(cfg.jobs)} job(s) render correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
