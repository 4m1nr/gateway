"""Print a credential from a fixture's primary outbound.

Used to assert that nothing world-readable ever contains it. Outbounds are
free-form now, so this digs out whichever credential shape the protocol uses.
"""

import sys

sys.path.insert(0, "lib")
import gwconfig  # noqa: E402


def main(path: str) -> int:
    ob = gwconfig.load(path).server["outbound"]
    settings = ob.get("settings", {})
    for entry in settings.get("vnext", []):
        for user in entry.get("users", []):
            if user.get("id"):
                print(user["id"])
                return 0
    for server in settings.get("servers", []):
        for key in ("password", "id"):
            if server.get(key):
                print(server[key])
                return 0
        for user in server.get("users", []):
            if user.get("id"):
                print(user["id"])
                return 0
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
