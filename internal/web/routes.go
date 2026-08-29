package web

import (
	"net/http"

	"github.com/am1nr/gateway/internal/web/action"
	"github.com/am1nr/gateway/internal/webauth"
)

func (s *Server) routes() {
	mux := http.NewServeMux()

	// Unauthenticated. /api/session is how the page decides whether to show the
	// login form, so it must answer before there is a session.
	mux.HandleFunc("GET /api/session", s.handleSession)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)

	// Read-only.
	mux.HandleFunc("GET /api/status", s.authed(s.proxyGet("status")))
	mux.HandleFunc("GET /api/clients", s.authed(s.proxyGet("clients")))
	mux.HandleFunc("GET /api/jobs", s.authed(s.proxyGet("jobs")))
	mux.HandleFunc("GET /api/outbounds", s.authed(s.proxyGet("outbounds")))
	mux.HandleFunc("GET /api/config/generated", s.authed(s.proxyGet("generated_config")))
	mux.HandleFunc("GET /api/diff", s.authed(s.proxyGet("diff")))

	// Mutating. Each is a distinct action name, so the helper's whitelist is
	// the real authorisation surface rather than a URL pattern.
	mux.HandleFunc("POST /api/clients", s.authed(s.handleClientAdd))
	mux.HandleFunc("DELETE /api/clients/{ip}", s.authed(s.handleClientRemove))
	mux.HandleFunc("POST /api/jobs", s.authed(s.handleJobAdd))
	mux.HandleFunc("DELETE /api/jobs/{name}", s.authed(s.handleJobRemove))
	mux.HandleFunc("POST /api/jobs/{name}/toggle", s.authed(s.handleJobToggle))
	mux.HandleFunc("POST /api/outbounds/import", s.authed(s.handleImportLink))
	mux.HandleFunc("POST /api/units/{unit}/restart", s.authed(s.handleRestartUnit))
	mux.HandleFunc("POST /api/apply", s.authed(s.handleApply))

	// Everything else is the dashboard itself. Registered last and at the
	// root, so it never shadows an API route.
	mux.Handle("/", s.serveStatic())

	s.mux = mux
}

// proxyGet forwards a read-only action to the privileged helper.
func (s *Server) proxyGet(name string) func(http.ResponseWriter, *http.Request, *webauth.Session) {
	return func(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
		s.call(w, action.Request{Action: name})
	}
}

// ---------------------------------------------------------------- session --

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var sess *webauth.Session
	if c, err := r.Cookie(sessionCookie); err == nil {
		sess = s.Sessions.Get(c.Value, peerAddr(r))
	}

	// Whether a password exists is asked across the privilege boundary: this
	// process cannot read the hash file, by design.
	//
	// A failure here is reported as a failure. Folding it into
	// password_set = false told the owner to run `gw web-passwd`, which cannot
	// fix a helper that is not answering — and they ran it, repeatedly, while
	// the page went on saying no password was set.
	configured := false
	helperError := ""
	resp, err := s.Privileged.Call(action.Request{Action: "auth_status"})
	switch {
	case err != nil:
		helperError = err.Error()
		s.Log.Error("the privileged helper is not answering", "err", err)
	case !resp.OK:
		helperError = resp.Error
		s.Log.Error("the privileged helper refused auth_status", "err", resp.Error)
	default:
		configured, _ = resp.Data["password_set"].(bool)
	}

	body := map[string]any{
		"authenticated": sess != nil,
		"password_set":  configured,
		"helper_error":  helperError,
		"csrf":          nil,
	}
	if sess != nil {
		body["csrf"] = sess.CSRF
	}
	s.writeJSON(w, http.StatusOK, body)
}

type loginRequest struct {
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	peer := peerAddr(r)
	if wait := s.Lockout.LockedFor(peer); wait > 0 {
		s.Log.Warn("login attempt from a locked-out address", "peer", peer)
		s.fail(w, http.StatusTooManyRequests,
			"too many failed attempts — try again in %d min", int(wait.Minutes())+1)
		return
	}

	var req loginRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "could not read the request")
		return
	}

	// Verified by the root helper: the hash file is 0600 root:root and is never
	// readable by this process.
	resp, err := s.Privileged.Call(action.Request{Action: "verify_password", Password: req.Password})
	if err != nil || !resp.OK {
		// Include the reason. "Could not check the password" on its own sends
		// you looking at the password, not at the helper.
		detail := ""
		if err != nil {
			detail = ": " + firstLine(err.Error())
		} else if resp.Error != "" {
			detail = ": " + firstLine(resp.Error)
		}
		s.fail(w, http.StatusInternalServerError, "could not reach the privileged helper%s", detail)
		return
	}
	if set, _ := resp.Data["password_set"].(bool); !set {
		s.fail(w, http.StatusServiceUnavailable,
			"no dashboard password is set — run `sudo gw web-passwd` on the box")
		return
	}
	if valid, _ := resp.Data["valid"].(bool); !valid {
		s.Lockout.RecordFailure(peer)
		s.Log.Warn("failed login", "peer", peer)
		s.fail(w, http.StatusUnauthorized, "wrong password")
		return
	}

	s.Lockout.Clear(peer)
	token, sess := s.Sessions.Create(peer)
	s.Log.Info("login", "peer", peer)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.Settings.TLS,
		SameSite: http.SameSiteStrictMode,
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": sess.CSRF})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Sessions.Destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: s.Settings.TLS, SameSite: http.SameSiteStrictMode,
	})
	s.writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---------------------------------------------------------------- clients --

type clientRequest struct {
	IP     string `json:"ip"`
	Name   string `json:"name"`
	Policy string `json:"policy"`
}

func (s *Server) handleClientAdd(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	var req clientRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "could not read the request")
		return
	}
	s.Log.Info("client add", "peer", peerAddr(r), "ip", req.IP)
	s.call(w, action.Request{
		Action: "client_add", IP: req.IP, Name: req.Name, Policy: req.Policy,
	})
}

func (s *Server) handleClientRemove(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	ip := r.PathValue("ip")
	s.Log.Info("client remove", "peer", peerAddr(r), "ip", ip)
	s.call(w, action.Request{Action: "client_rm", IP: ip})
}

// ------------------------------------------------------------------- jobs --

type jobRequest struct {
	Name        string `json:"name"`
	Schedule    string `json:"schedule"`
	Script      string `json:"script"`
	User        string `json:"user"`
	Description string `json:"description"`
}

func (s *Server) handleJobAdd(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	var req jobRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "could not read the request")
		return
	}
	// Worth logging loudly: a job runs as root, so this is the most powerful
	// thing the dashboard can do.
	s.Log.Info("job saved", "peer", peerAddr(r), "job", req.Name, "user", req.User)
	s.call(w, action.Request{
		Action: "job_add", Name: req.Name, Schedule: req.Schedule,
		Script: req.Script, User: req.User, Description: req.Description,
	})
}

func (s *Server) handleJobRemove(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	name := r.PathValue("name")
	s.Log.Info("job removed", "peer", peerAddr(r), "job", name)
	s.call(w, action.Request{Action: "job_rm", Name: name})
}

type toggleRequest struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleJobToggle(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	var req toggleRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "could not read the request")
		return
	}
	s.call(w, action.Request{
		Action: "job_toggle", Name: r.PathValue("name"), Enabled: req.Enabled,
	})
}

// -------------------------------------------------------------- outbounds --

type importRequest struct {
	Link string `json:"link"`
}

func (s *Server) handleImportLink(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	var req importRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, http.StatusBadRequest, "could not read the request")
		return
	}
	// Deliberately not logged: a share link carries the server's credentials.
	s.call(w, action.Request{Action: "import_link", Link: req.Link})
}

// ------------------------------------------------------------------ units --

func (s *Server) handleRestartUnit(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	unit := r.PathValue("unit")
	s.Log.Info("unit restart", "peer", peerAddr(r), "unit", unit)
	s.call(w, action.Request{Action: "restart_unit", Unit: unit})
}

// ----------------------------------------------------------------- apply --

func (s *Server) handleApply(w http.ResponseWriter, r *http.Request, _ *webauth.Session) {
	s.Log.Info("apply", "peer", peerAddr(r))
	s.call(w, action.Request{Action: "apply"})
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}
