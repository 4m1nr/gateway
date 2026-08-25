"""Password hashing, sessions and login lockout for the dashboard.

Stdlib only: scrypt for the password, secrets for tokens, hmac for every
comparison. The password file lives outside the repo and is never rendered.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import pathlib
import secrets
import time

AUTH_FILE = pathlib.Path("/etc/gateway/web-auth.json")

# ~64 MB, ~100 ms per attempt on thin-client hardware. Slow enough that the
# lockout does the real work but a legitimate login still feels instant.
SCRYPT = {"n": 2**15, "r": 8, "p": 1, "dklen": 32, "maxmem": 96 * 1024 * 1024}


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, **SCRYPT)
    return salt.hex(), dk.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        _, dk = hash_password(password, bytes.fromhex(salt_hex))
    except ValueError:
        return False
    return hmac.compare_digest(dk, hash_hex)


def save_password(password: str, path: pathlib.Path = AUTH_FILE) -> None:
    salt, digest = hash_password(password)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written 0600 before any content lands in it.
    fd = path.open("w")
    try:
        path.chmod(0o600)
        json.dump({"salt": salt, "hash": digest, "updated": int(time.time())}, fd)
    finally:
        fd.close()


def load_password(path: pathlib.Path = AUTH_FILE) -> dict | None:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


class Sessions:
    """In-memory sessions. A restart logs everyone out, which is the right
    trade for a box whose whole job is to be restarted when things break."""

    def __init__(self, ttl_hours: int = 12):
        self.ttl = ttl_hours * 3600
        self._store: dict[str, dict] = {}

    def create(self, peer: str) -> str:
        token = secrets.token_urlsafe(32)
        self._store[token] = {
            "peer": peer,
            "expires": time.time() + self.ttl,
            "csrf": secrets.token_urlsafe(24),
        }
        return token

    def get(self, token: str | None, peer: str) -> dict | None:
        if not token:
            return None
        self._reap()
        for known, data in self._store.items():
            if hmac.compare_digest(known, token):
                # A session is bound to the address that created it, so a
                # stolen cookie is not portable to another host.
                if data["peer"] != peer:
                    return None
                return data
        return None

    def destroy(self, token: str | None) -> None:
        if token:
            self._store.pop(token, None)

    def _reap(self) -> None:
        now = time.time()
        for token in [t for t, d in self._store.items() if d["expires"] < now]:
            del self._store[token]


class Lockout:
    """Per-address failed-login throttle."""

    def __init__(self, max_failures: int = 5, minutes: int = 15):
        self.max = max_failures
        self.window = minutes * 60
        self._fails: dict[str, list[float]] = {}

    def locked_for(self, peer: str) -> int:
        """Seconds remaining, 0 if not locked."""
        now = time.time()
        recent = [t for t in self._fails.get(peer, []) if now - t < self.window]
        self._fails[peer] = recent
        if len(recent) >= self.max:
            return int(self.window - (now - recent[0])) + 1
        return 0

    def record_failure(self, peer: str) -> None:
        self._fails.setdefault(peer, []).append(time.time())

    def clear(self, peer: str) -> None:
        self._fails.pop(peer, None)


def peer_allowed(peer: str, allow_cidrs: list[str]) -> bool:
    """Is this source address permitted to reach the dashboard at all?

    `peer` must come from the socket. Never pass a value derived from a header:
    nothing proxies this service, so X-Forwarded-For can only be a forgery.
    """
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for cidr in allow_cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False
