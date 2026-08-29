// Package web serves the dashboard.
//
// The dashboard can rewrite the firewall, so it is fenced four independent
// ways:
//
//  1. Source address — nftables only accepts the port from web.allow_cidrs,
//     and this process re-checks the peer itself. The address comes from the
//     socket; X-Forwarded-For is ignored, because nothing proxies this service
//     and a header claiming otherwise can only be a forgery.
//  2. Password — scrypt, with a per-address lockout. Sessions are bound to the
//     address that created them, so a stolen cookie is not portable.
//  3. CSRF token — on every mutating request, on top of a SameSite=Strict
//     cookie.
//  4. Privilege separation — this process runs as gwweb and can do nothing on
//     its own. Every privileged action is a JSON request piped to one sudo
//     entry point, which re-validates every field as root.
package web

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/am1nr/gateway/internal/web/action"
	"github.com/am1nr/gateway/internal/webauth"
)

// Settings is /etc/gateway/web.json, rendered by `gw apply`.
//
// It deliberately contains no secrets: the password hash lives in
// /etc/gateway/web-auth.json, 0600 root:root, and is never rendered.
type Settings struct {
	Listen          string   `json:"listen"`
	Port            int      `json:"port"`
	TLS             bool     `json:"tls"`
	Cert            string   `json:"cert"`
	Key             string   `json:"key"`
	AllowCIDRs      []string `json:"allow_cidrs"`
	SessionHours    int      `json:"session_hours"`
	MaxFailedLogins int      `json:"max_failed_logins"`
	LockoutMinutes  int      `json:"lockout_minutes"`
}

// sessionCookie is the cookie name. Prefixed __Host- under TLS by the setter.
const sessionCookie = "gw_session"

// Server is the dashboard.
type Server struct {
	Settings   Settings
	Sessions   *webauth.Sessions
	Lockout    *webauth.Lockout
	Privileged Caller
	Log        *slog.Logger

	mux *http.ServeMux
}

// New builds a server from settings.
func New(s Settings, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	srv := &Server{
		Settings: s,
		Sessions: webauth.NewSessions(s.SessionHours),
		Lockout:  webauth.NewLockout(s.MaxFailedLogins, s.LockoutMinutes),
		Log:      log,
	}
	srv.routes()
	return srv
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Gate 1, before routing: an address that may not reach the dashboard does
	// not get to probe which endpoints exist.
	peer := peerAddr(r)
	if !webauth.PeerAllowed(peer, s.Settings.AllowCIDRs) {
		s.Log.Warn("rejected a request from an address outside allow_cidrs", "peer", peer)
		s.writeJSON(w, http.StatusForbidden, map[string]any{
			"error": "your address is not permitted",
		})
		return
	}
	s.mux.ServeHTTP(w, r)
}

// peerAddr returns the address from the socket.
//
// Never derived from a header. Nothing proxies this service, so an
// X-Forwarded-For claiming a permitted source could only be an attempt to get
// past the first gate.
func peerAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// -------------------------------------------------------------- responses --

// csp is strict because it can be: the assets are files we serve ourselves.
//
// style-src allows 'unsafe-inline' and nothing else does. The component library
// positions overlays by setting element styles at runtime, which is a style
// attribute, not a script. Scripts stay 'self' only, which is the directive
// that actually matters here.
const csp = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"font-src 'self'; connect-src 'self'; img-src 'self' data:; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func (s *Server) securityHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", csp)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	if s.Settings.TLS {
		h.Set("Strict-Transport-Security", "max-age=31536000")
	}
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, body any) {
	s.securityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(body)
}

func (s *Server) fail(w http.ResponseWriter, status int, format string, a ...any) {
	msg := format
	if len(a) > 0 {
		msg = fmt.Sprintf(format, a...)
	}
	s.writeJSON(w, status, map[string]any{"error": msg})
}

// ------------------------------------------------------------------ gates --

// session returns the caller's session, or nil after writing a 401.
func (s *Server) session(w http.ResponseWriter, r *http.Request) *webauth.Session {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		s.fail(w, http.StatusUnauthorized, "not authenticated")
		return nil
	}
	sess := s.Sessions.Get(c.Value, peerAddr(r))
	if sess == nil {
		s.fail(w, http.StatusUnauthorized, "not authenticated")
		return nil
	}
	return sess
}

// checkCSRF is gate 3, on top of a SameSite=Strict cookie.
func (s *Server) checkCSRF(w http.ResponseWriter, r *http.Request, sess *webauth.Session) bool {
	token := r.Header.Get("X-CSRF-Token")
	if token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) == 1 {
		return true
	}
	s.fail(w, http.StatusForbidden, "bad or missing CSRF token")
	return false
}

// authed wraps a handler that needs a session; mutating verbs also need CSRF.
func (s *Server) authed(fn func(http.ResponseWriter, *http.Request, *webauth.Session)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := s.session(w, r)
		if sess == nil {
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if !s.checkCSRF(w, r, sess) {
				return
			}
		}
		fn(w, r, sess)
	}
}

// ------------------------------------------------------------ privileged --

// call runs one privileged action and writes its result.
func (s *Server) call(w http.ResponseWriter, req action.Request) {
	resp, err := s.Privileged.Call(req)
	if err != nil {
		s.Log.Error("the privileged helper failed", "action", req.Action, "err", err)
		s.fail(w, http.StatusInternalServerError, "%s", err.Error())
		return
	}
	if !resp.OK {
		s.fail(w, http.StatusBadRequest, "%s", resp.Error)
		return
	}
	body := map[string]any{"ok": true}
	for k, v := range resp.Data {
		body[k] = v
	}
	if resp.Message != "" {
		body["message"] = resp.Message
	}
	if resp.PendingApply {
		body["pending_apply"] = true
	}
	s.writeJSON(w, http.StatusOK, body)
}

// decode reads a bounded JSON body.
//
// A bounded reader rather than an unbounded one: this endpoint accepts job
// scripts, so the limit is generous, but "generous" and "unlimited" are
// different things on a box with 2 GB of RAM.
func decode(r *http.Request, dst any) error {
	const maxBody = 256 * 1024
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBody))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

// ---------------------------------------------------------------- serving --

// ListenAndServe starts the dashboard.
func (s *Server) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: s,
		// http.Server's zero timeouts mean a slow client can hold a connection
		// open forever. This is a LAN service on a thin client; a handful of
		// stuck connections is a meaningful fraction of it.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Generous: `apply` legitimately takes minutes, and log streaming is
		// open-ended, so the write deadline is managed per-handler instead.
		WriteTimeout: 0,
		IdleTimeout:  120 * time.Second,
	}
	if s.Settings.TLS {
		return srv.ListenAndServeTLS(s.Settings.Cert, s.Settings.Key)
	}
	return srv.ListenAndServe()
}
