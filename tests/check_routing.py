"""Assert the Xray rule ORDER, which is where profile semantics actually live.

Xray takes the first matching rule, so these relative positions are the whole
behaviour:

  profile exception  <  global geo split  <  profile fallthrough  <  default

If an exception slipped below the geo rules, "send corp.example.ir via work"
would silently lose to "all .ir goes direct" — a bug you would only notice by
watching where work traffic actually came out.
"""

from __future__ import annotations

import json
import sys


def index_of(rules, pred) -> int:
    for i, r in enumerate(rules):
        if pred(r):
            return i
    return -1


def main(config_path: str) -> int:
    rules = json.load(open(config_path))["routing"]["rules"]
    problems = []

    geo = index_of(rules, lambda r: r.get("outboundTag") == "direct"
                   and any(str(d).startswith("geosite:") for d in r.get("domain", [])))
    if geo < 0:
        print("skip: no global geosite rule in this config")
        return 0

    # Every source-scoped rule that names a non-default outbound is an exception.
    exceptions = [i for i, r in enumerate(rules)
                  if r.get("source") and (r.get("domain") or r.get("ip"))]
    fallthroughs = [i for i, r in enumerate(rules)
                    if r.get("source") and not r.get("domain") and not r.get("ip")
                    and r.get("outboundTag") in ("proxy", "direct")]

    for i in exceptions:
        if i > geo:
            problems.append(
                f"exception rule #{i} ({rules[i].get('outboundTag')}) comes AFTER "
                f"the global geo split at #{geo} — the geo rule will win"
            )

    # The fallthrough must be below the geo rules, or a profile client loses the
    # domestic-direct split entirely.
    for i in fallthroughs:
        srcs = rules[i]["source"]
        # `direct` policy clients are also source-scoped fallthroughs, but they
        # are placed above deliberately: they never reach Xray at all.
        if i < geo and rules[i].get("outboundTag") == "proxy":
            problems.append(
                f"profile fallthrough #{i} for {srcs} comes BEFORE the geo split "
                f"at #{geo} — that client loses domestic-direct routing"
            )

    last = rules[-1]
    if last.get("source"):
        problems.append("the final rule is source-scoped; there is no catch-all")

    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print(f"ok: {len(exceptions)} exception(s) before the geo split at #{geo}, "
          f"{len(fallthroughs)} fallthrough(s) after it")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
