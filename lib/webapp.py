"""Gateway dashboard: status + client management over HTTP(S).

Runs unprivileged as `gwweb`. It cannot touch the firewall, the config or
systemd itself — every privileged action goes through one sudo entry point
(web-action.py) which re-validates the request as root.

Three independent gates, in order: source address, session, CSRF token.

http.server is not a hardened internet-facing server, and this is not exposed
to the internet: it binds a LAN address, nftables only accepts the port from
allow_cidrs, and the app re-checks the peer. Keep it that way.
"""

from __future__ import annotations

import http.cookies
import json
import logging
import pathlib
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import webauth

SETTINGS = pathlib.Path("/etc/gateway/web.json")
WEBROOT = pathlib.Path("/usr/local/share/gateway/web")
ACTION = "/usr/local/lib/gateway/web-action.py"
MAX_BODY = 64 * 1024
COOKIE = "gw_session"

STATIC = {
    "/": ("dashboard.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}

# Strict because we can be: CSS and JS are separate files we serve ourselves,
# so nothing inline needs to be allowed.
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self' data:; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
)

log = logging.getLogger("gw-web")


def load_settings() -> dict:
    try:
        return json.loads(SETTINGS.read_text())
    except (OSError, ValueError) as e:
        sys.exit(f"cannot read {SETTINGS}: {e} (run `sudo gw apply`)")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gw"
    sys_version = ""

    # -------------------------------------------------------------- helpers --
    @property
    def peer(self) -> str:
        return self.client_address[0]

    def log_message(self, fmt, *args):
        log.info("%s %s", self.peer, fmt % args)

    def send_json(self, obj, status=200, extra_headers=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._security_headers()
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _security_headers(self):
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if self.server.settings.get("tls"):
            self.send_header("Strict-Transport-Security", "max-age=31536000")

    def cookie_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        try:
            jar = http.cookies.SimpleCookie(raw)
        except http.cookies.CookieError:
            return None
        morsel = jar.get(COOKIE)
        return morsel.value if morsel else None

    def read_body(self) -> dict | None:
        """None means "refuse this request" — an oversized or unreadable body.

        Returning {} instead would let a 10 MB POST look like an empty one, and
        leaving the bytes unread desyncs the next request on a keep-alive
        connection.
        """
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length > MAX_BODY:
            return None
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return {}

    def reject_body(self):
        self.send_json(
            {"error": f"request body too large (limit {MAX_BODY} bytes)"},
            413,
            extra_headers={"Connection": "close"},
        )
        self.close_connection = True

    # ---------------------------------------------------------------- gates --
    def gate_peer(self) -> bool:
        """Gate 1: is this address allowed to reach the dashboard at all?

        self.client_address comes from the socket. X-Forwarded-For is ignored
        on purpose — nothing proxies this service, so such a header could only
        be an attempt to spoof an allowed source.
        """
        if webauth.peer_allowed(self.peer, self.server.settings["allow_cidrs"]):
            return True
        log.warning("rejected %s: not in allow_cidrs", self.peer)
        self.send_json({"error": "your address is not permitted"}, 403)
        return False

    def gate_session(self) -> dict | None:
        """Gate 2: a valid session bound to this same address."""
        session = self.server.sessions.get(self.cookie_token(), self.peer)
        if session is None:
            self.send_json({"error": "not authenticated"}, 401)
            return None
        return session

    def gate_csrf(self, session: dict) -> bool:
        """Gate 3: CSRF token, on top of a SameSite=Strict cookie."""
        import hmac

        token = self.headers.get("X-CSRF-Token", "")
        if token and hmac.compare_digest(token, session["csrf"]):
            return True
        self.send_json({"error": "bad or missing CSRF token"}, 403)
        return False

    # ------------------------------------------------------------ privileged --
    def privileged(self, request: dict) -> tuple[bool, dict]:
        """Hand a request to the root helper. Nothing here builds a shell
        command; the payload travels over stdin as JSON."""
        try:
            proc = subprocess.run(
                ["sudo", "-n", ACTION],
                input=json.dumps(request),
                capture_output=True,
                text=True,
                timeout=310,
            )
        except subprocess.TimeoutExpired:
            return False, {"error": "the action timed out"}
        if proc.stdout.strip():
            try:
                data = json.loads(proc.stdout)
                return bool(data.get("ok")), data
            except ValueError:
                pass
        return False, {"error": (proc.stderr.strip() or "privileged helper failed")[:500]}

    # ----------------------------------------------------------------- verbs --
    def do_GET(self):
        if not self.gate_peer():
            return
        path = self.path.split("?", 1)[0]

        if path in STATIC:
            return self.serve_static(*STATIC[path])

        if path == "/api/session":
            session = self.server.sessions.get(self.cookie_token(), self.peer)
            ok, data = self.privileged({"action": "auth_status"})
            configured = bool(ok and data.get("password_set"))
            return self.send_json(
                {
                    "authenticated": session is not None,
                    "csrf": session["csrf"] if session else None,
                    "password_set": configured,
                }
            )

        gets = {"/api/status": "status", "/api/clients": "clients",
                "/api/jobs": "jobs"}
        if path in gets:
            session = self.gate_session()
            if session is None:
                return
            ok, data = self.privileged({"action": gets[path]})
            return self.send_json(data, 200 if ok else 500)

        self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if not self.gate_peer():
            return
        path = self.path.split("?", 1)[0]

        if path == "/api/login":
            return self.do_login()
        if path == "/api/logout":
            token = self.cookie_token()
            self.server.sessions.destroy(token)
            return self.send_json(
                {"ok": True},
                extra_headers={"Set-Cookie": f"{COOKIE}=; Path=/; Max-Age=0; HttpOnly"},
            )

        session = self.gate_session()
        if session is None:
            return
        if not self.gate_csrf(session):
            return

        body = self.read_body()
        if body is None:
            return self.reject_body()
        routes = {
            "/api/clients": lambda: {"action": "client_add", **{
                k: body.get(k) for k in ("ip", "name", "policy")}},
            "/api/clients/delete": lambda: {"action": "client_rm", "ip": body.get("ip")},
            "/api/jobs": lambda: {"action": "job_add", **{
                k: body.get(k) for k in
                ("name", "schedule", "script", "user", "description")}},
            "/api/jobs/delete": lambda: {"action": "job_rm", "name": body.get("name")},
            "/api/jobs/toggle": lambda: {
                "action": "job_toggle", "name": body.get("name"),
                "enabled": bool(body.get("enabled"))},
            "/api/apply": lambda: {"action": "apply"},
            "/api/probe": lambda: {"action": "probe"},
        }
        if path not in routes:
            return self.send_json({"error": "not found"}, 404)

        log.info("%s action %s", self.peer, path)
        ok, data = self.privileged(routes[path]())
        return self.send_json(data, 200 if ok else 400)

    def do_login(self):
        locked = self.server.lockout.locked_for(self.peer)
        if locked:
            log.warning("locked-out login attempt from %s", self.peer)
            return self.send_json(
                {"error": f"too many failed attempts — try again in {locked // 60 + 1} min"},
                429,
            )

        body = self.read_body()
        if body is None:
            return self.reject_body()
        password = body.get("password", "")
        if not isinstance(password, str):
            password = ""
        # Verified by the root helper: the hash file is 0600 root:root and is
        # never readable by this process.
        ok, result = self.privileged({"action": "verify_password", "password": password})
        if not ok:
            return self.send_json({"error": "could not check the password"}, 500)
        if not result.get("password_set"):
            return self.send_json(
                {"error": "no dashboard password is set — run `sudo gw web-passwd` on the box"},
                503,
            )
        if not result.get("valid"):
            self.server.lockout.record_failure(self.peer)
            log.warning("failed login from %s", self.peer)
            return self.send_json({"error": "wrong password"}, 401)

        self.server.lockout.clear(self.peer)
        token = self.server.sessions.create(self.peer)
        session = self.server.sessions.get(token, self.peer)
        log.info("login from %s", self.peer)
        flags = "HttpOnly; SameSite=Strict; Path=/"
        if self.server.settings.get("tls"):
            flags += "; Secure"
        return self.send_json(
            {"ok": True, "csrf": session["csrf"]},
            extra_headers={"Set-Cookie": f"{COOKIE}={token}; {flags}"},
        )

    def serve_static(self, filename: str, ctype: str):
        path = WEBROOT / filename
        try:
            body = path.read_bytes()
        except OSError:
            return self.send_json({"error": "asset missing"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    logging.basicConfig(
        format="%(levelname)s %(message)s", level=logging.INFO, stream=sys.stdout
    )
    settings = load_settings()

    httpd = ThreadingHTTPServer((settings["listen"], settings["port"]), Handler)
    httpd.settings = settings
    httpd.sessions = webauth.Sessions(settings.get("session_hours", 12))
    httpd.lockout = webauth.Lockout(
        settings.get("max_failed_logins", 5), settings.get("lockout_minutes", 15)
    )

    scheme = "http"
    if settings.get("tls"):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            ctx.load_cert_chain(settings["cert"], settings["key"])
        except OSError as e:
            sys.exit(f"cannot load the TLS certificate: {e} (run scripts/40-web.sh)")
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    log.info(
        "listening on %s://%s:%s, allowing %s",
        scheme, settings["listen"], settings["port"], ", ".join(settings["allow_cidrs"]),
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
