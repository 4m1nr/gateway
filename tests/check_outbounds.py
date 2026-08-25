"""Assert the invariants the gateway enforces on user-supplied outbounds.

Outbounds are now pasted verbatim, so the two things the gateway must impose on
every one of them are exactly the two things nobody writing an outbound by hand
would think to include:

  tag           routing rules reference it by name
  sockopt.mark  the loop guard — an outbound without it makes Xray's own
                packets eligible for TPROXY, and the box deadlocks the moment
                interception is enabled

This is the highest-consequence check in the suite: it is the difference
between a working gateway and one that wedges on boot.
"""

from __future__ import annotations

import json
import sys


def main(config_path: str, expected_mark: int) -> int:
    conf = json.load(open(config_path))
    problems = []
    tags = []

    for i, ob in enumerate(conf["outbounds"]):
        tag = ob.get("tag")
        tags.append(tag)
        if not tag:
            problems.append(f"outbound #{i} has no tag")
        if ob.get("protocol") == "blackhole":
            continue  # never leaves the box
        mark = ob.get("streamSettings", {}).get("sockopt", {}).get("mark")
        if mark is None:
            problems.append(
                f"outbound {tag!r} has no sockopt.mark — its packets would be "
                "re-captured by TPROXY and the gateway would deadlock"
            )
        elif int(mark) != expected_mark:
            problems.append(
                f"outbound {tag!r} has mark {mark}, expected {expected_mark}"
            )

    if len(set(tags)) != len(tags):
        problems.append(f"duplicate outbound tags: {tags}")

    referenced = {
        r.get("outboundTag") for r in conf["routing"]["rules"] if r.get("outboundTag")
    }
    for bal in conf["routing"].get("balancers", []):
        referenced.update(bal.get("selector", []))
    unknown = referenced - set(tags) - {"api"}
    if unknown:
        problems.append(f"routing references outbounds that do not exist: {sorted(unknown)}")

    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        return 1
    print(f"ok: {len(tags)} outbounds, all tagged and marked ({', '.join(map(str, tags))})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], int(sys.argv[2])))
