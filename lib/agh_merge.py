"""Merge gw's desired AdGuard settings into AdGuardHome.yaml.

Deep-merges dicts, replaces lists wholesale (a half-merged upstream list is
worse than either version). Leaves users, schema_version and anything else
AdGuard manages untouched.
"""

from __future__ import annotations

import json
import shutil
import sys

try:
    import yaml
except ModuleNotFoundError:
    sys.exit("python3-yaml is not installed (apt install python3-yaml)")


def deep_merge(base: dict, new: dict) -> dict:
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            deep_merge(base[k], v)
        else:
            base[k] = v
    return base


def main(yaml_path: str, overrides_path: str) -> int:
    with open(overrides_path) as fh:
        new = json.load(fh)

    try:
        with open(yaml_path) as fh:
            cur = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        print(f"{yaml_path} does not exist yet — start AdGuard Home once, "
              "complete the setup wizard, then re-run `gw apply`.", file=sys.stderr)
        return 1

    shutil.copy2(yaml_path, yaml_path + ".bak")
    merged = deep_merge(cur, new)
    with open(yaml_path, "w") as fh:
        yaml.safe_dump(merged, fh, sort_keys=False, default_flow_style=False)
    print(f"merged gateway settings into {yaml_path} (backup: {yaml_path}.bak)")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: agh_merge.py <AdGuardHome.yaml> <overrides.json>")
    sys.exit(main(sys.argv[1], sys.argv[2]))
