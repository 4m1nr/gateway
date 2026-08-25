"""Assert custom routing rules land at the position they asked for.

Xray takes the first matching rule, so "position" is not cosmetic:

  first   ahead of per-client policy — a hard block that no device escapes
  before  after per-client policy, ahead of the geo split
  after   after the geo split, before the fallthrough defaults

Getting this wrong produces no error. A "first" block that drifted below the
per-client rules would simply stop applying to devices with an explicit policy.
"""

from __future__ import annotations

import json
import sys

sys.path.insert(0, "lib")
import gwconfig  # noqa: E402


def main(toml_path: str, config_path: str) -> int:
    cfg = gwconfig.load(toml_path)
    rules = json.load(open(config_path))["routing"]["rules"]
    problems = []

    def find(rule: dict) -> int:
        for i, r in enumerate(rules):
            if all(r.get(k) == v for k, v in rule.items()):
                return i
        return -1

    # Landmarks the positions are defined against.
    client_rules = [i for i, r in enumerate(rules) if r.get("source")]
    first_client = min(client_rules) if client_rules else len(rules)
    geo = next(
        (i for i, r in enumerate(rules)
         if r.get("outboundTag") == "direct"
         and any(str(d).startswith("geosite:") for d in r.get("domain", []))),
        -1,
    )

    counts = {"first": 0, "before": 0, "after": 0}
    for entry in cfg.routes:
        pos, rule = entry["position"], entry["rule"]
        at = find(rule)
        if at < 0:
            problems.append(f"{pos} rule {rule} never made it into the config")
            continue
        counts[pos] += 1
        if pos == "first" and at > first_client:
            problems.append(
                f"'first' rule at #{at} is below the per-client rules "
                f"(#{first_client}) — devices with an explicit policy escape it"
            )
        if pos == "before" and geo >= 0 and at > geo:
            problems.append(
                f"'before' rule at #{at} is below the geo split (#{geo}) — "
                "the geo rule will win"
            )
        if pos == "after" and geo >= 0 and at < geo:
            problems.append(
                f"'after' rule at #{at} is above the geo split (#{geo})"
            )

    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print(f"ok: custom routes placed correctly "
          f"({counts['first']} first, {counts['before']} before, {counts['after']} after)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
