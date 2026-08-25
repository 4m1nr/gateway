"""`gw web-passwd` — set the dashboard password.

Runs as root. The hash file is 0600 root:root and is never readable by the web
process; logins are verified across the sudo boundary instead.
"""

from __future__ import annotations

import getpass
import os
import sys

import webauth

MIN_LEN = 10


def main() -> int:
    if os.geteuid() != 0:
        print("web-passwd must run as root (sudo gw web-passwd)", file=sys.stderr)
        return 1

    existing = webauth.load_password() is not None
    print(f"Setting the dashboard password ({'replacing the current one' if existing else 'first time'}).")
    print(f"Minimum {MIN_LEN} characters. It is stored scrypt-hashed, never in the repo.\n")

    try:
        first = getpass.getpass("New password: ")
        second = getpass.getpass("Repeat: ")
    except (KeyboardInterrupt, EOFError):
        print("\naborted")
        return 1

    if first != second:
        print("passwords do not match", file=sys.stderr)
        return 1
    if len(first) < MIN_LEN:
        print(f"too short — use at least {MIN_LEN} characters", file=sys.stderr)
        return 1

    webauth.save_password(first)
    os.chown(webauth.AUTH_FILE, 0, 0)
    os.chmod(webauth.AUTH_FILE, 0o600)
    print(f"\nsaved to {webauth.AUTH_FILE} (0600 root:root)")
    print("Existing dashboard sessions stay valid until they expire;")
    print("run 'systemctl restart gw-web' to sign everyone out now.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
