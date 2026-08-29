package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/web/action"
)

// fakeHelper stands in for the root helper, recording what it was asked.
type fakeHelper struct {
	calls    []action.Request
	password string
	respond  func(action.Request) action.Response
}

func (f *fakeHelper) handle(req action.Request) action.Response {
	f.calls = append(f.calls, req)
	if f.respond != nil {
		return f.respond(req)
	}
	switch req.Action {
	case "auth_status":
		return action.Response{OK: true, Data: map[string]any{"password_set": f.password != ""}}
	case "verify_password":
		return action.Response{OK: true, Data: map[string]any{
			"password_set": f.password != "",
			"valid":        req.Password == f.password,
		}}
	}
	return action.Response{OK: true, Data: map[string]any{"action": req.Action}}
}

// newTestServer wires a Server to a fake helper installed as a shell script, so
// the real sudo/systemd-run call path is exercised end to end.
func newTestServer(t *testing.T, helper *fakeHelper) *Server {
	t.Helper()
	s := New(Settings{
		AllowCIDRs:      []string{"192.168.1.0/24", "127.0.0.0/8"},
		SessionHours:    12,
		MaxFailedLogins: 3,
		LockoutMinutes:  15,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.Privileged = helper
	return s
}

// Call makes fakeHelper a Caller, so the HTTP gates are exercised without sudo.
func (f *fakeHelper) Call(req action.Request) (action.Response, error) {
	return f.handle(req), nil
}

// request issues an HTTP request from a given peer address.
func request(t *testing.T, s *Server, method, path, peer, body string,
	headers map[string]string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	r.RemoteAddr = peer + ":51234"
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

// Gate 1. An address outside allow_cidrs must be refused before routing, so it
// cannot even learn which endpoints exist.
func TestPeerOutsideAllowCIDRsIsRefusedEverywhere(t *testing.T) {
	s := newTestServer(t, &fakeHelper{})
	for _, path := range []string{"/api/session", "/api/status", "/api/login", "/api/clients"} {
		w := request(t, s, "GET", path, "8.8.8.8", "", nil, nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s from an outside address returned %d, want 403", path, w.Code)
		}
		if strings.Contains(w.Body.String(), "not authenticated") {
			t.Errorf("%s leaked that the endpoint exists", path)
		}
	}
}

// The peer must come from the socket. Nothing proxies this service, so an
// X-Forwarded-For claiming a permitted source could only be an attempt to get
// past the first gate.
func TestForwardedHeadersCannotForgeAPermittedAddress(t *testing.T) {
	s := newTestServer(t, &fakeHelper{})
	for _, header := range []string{"X-Forwarded-For", "X-Real-IP", "Forwarded"} {
		w := request(t, s, "GET", "/api/session", "8.8.8.8", "",
			map[string]string{header: "192.168.1.50"}, nil)
		if w.Code != http.StatusForbidden {
			t.Errorf("%s let an outside address through (got %d)", header, w.Code)
		}
	}
}

// Gate 2. Every data endpoint requires a session.
func TestDataEndpointsRequireASession(t *testing.T) {
	s := newTestServer(t, &fakeHelper{})
	for _, tc := range []struct{ method, path string }{
		{"GET", "/api/status"},
		{"GET", "/api/clients"},
		{"GET", "/api/jobs"},
		{"GET", "/api/outbounds"},
		{"GET", "/api/config/generated"},
		{"POST", "/api/clients"},
		{"DELETE", "/api/clients/192.168.1.5"},
		{"POST", "/api/jobs"},
		{"POST", "/api/units/xray.service/restart"},
	} {
		w := request(t, s, tc.method, tc.path, "192.168.1.50", "{}", nil, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s without a session returned %d, want 401", tc.method, tc.path, w.Code)
		}
	}
}

// login performs a successful login and returns the cookie and CSRF token.
func login(t *testing.T, s *Server, peer, password string) (*http.Cookie, string) {
	t.Helper()
	w := request(t, s, "POST", "/api/login", peer,
		`{"password":`+quote(password)+`}`, nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		CSRF string `json:"csrf"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	res := w.Result()
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie {
			return c, body.CSRF
		}
	}
	t.Fatal("login issued no session cookie")
	return nil, ""
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Gate 3. A valid session is not enough for a mutating request.
func TestMutatingRequestsRequireCSRF(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, csrf := login(t, s, "192.168.1.50", "hunter2hunter2")

	// Without the token.
	w := request(t, s, "POST", "/api/clients", "192.168.1.50",
		`{"ip":"192.168.1.9","name":"nas","policy":"proxy"}`, nil, []*http.Cookie{cookie})
	if w.Code != http.StatusForbidden {
		t.Errorf("a POST without a CSRF token returned %d, want 403", w.Code)
	}

	// With the wrong token.
	w = request(t, s, "POST", "/api/clients", "192.168.1.50",
		`{"ip":"192.168.1.9","name":"nas","policy":"proxy"}`,
		map[string]string{"X-CSRF-Token": "wrong"}, []*http.Cookie{cookie})
	if w.Code != http.StatusForbidden {
		t.Errorf("a POST with a wrong CSRF token returned %d, want 403", w.Code)
	}

	// With the right token.
	w = request(t, s, "POST", "/api/clients", "192.168.1.50",
		`{"ip":"192.168.1.9","name":"nas","policy":"proxy"}`,
		map[string]string{"X-CSRF-Token": csrf}, []*http.Cookie{cookie})
	if w.Code != http.StatusOK {
		t.Errorf("a correctly authenticated POST returned %d: %s", w.Code, w.Body.String())
	}
}

// A GET does not need CSRF: it changes nothing, and requiring it would break
// the first page load.
func TestReadsDoNotRequireCSRF(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, _ := login(t, s, "192.168.1.50", "hunter2hunter2")
	w := request(t, s, "GET", "/api/status", "192.168.1.50", "", nil, []*http.Cookie{cookie})
	if w.Code != http.StatusOK {
		t.Errorf("an authenticated GET returned %d: %s", w.Code, w.Body.String())
	}
}

// A session is bound to the address that created it, so a stolen cookie is not
// portable to another host on the same LAN.
func TestStolenCookieIsNotPortable(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, _ := login(t, s, "192.168.1.50", "hunter2hunter2")
	// Same LAN, different device — still inside allow_cidrs, so gate 1 passes.
	w := request(t, s, "GET", "/api/status", "192.168.1.51", "", nil, []*http.Cookie{cookie})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a cookie was accepted from a different address (got %d)", w.Code)
	}
}

func TestLockoutAfterRepeatedWrongPasswords(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	for i := 0; i < 3; i++ {
		w := request(t, s, "POST", "/api/login", "192.168.1.50", `{"password":"wrong"}`, nil, nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d returned %d, want 401", i+1, w.Code)
		}
	}
	w := request(t, s, "POST", "/api/login", "192.168.1.50", `{"password":"hunter2hunter2"}`, nil, nil)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("a locked-out address returned %d, want 429", w.Code)
	}
	// The lockout is per address: one attacker must not lock out the household.
	w = request(t, s, "POST", "/api/login", "192.168.1.51", `{"password":"hunter2hunter2"}`, nil, nil)
	if w.Code != http.StatusOK {
		t.Errorf("a different address was locked out too (got %d)", w.Code)
	}
}

// Signing out must actually invalidate the session server-side, not just clear
// the cookie in the browser.
func TestLogoutInvalidatesTheSessionServerSide(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, csrf := login(t, s, "192.168.1.50", "hunter2hunter2")
	request(t, s, "POST", "/api/logout", "192.168.1.50", "",
		map[string]string{"X-CSRF-Token": csrf}, []*http.Cookie{cookie})

	w := request(t, s, "GET", "/api/status", "192.168.1.50", "", nil, []*http.Cookie{cookie})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("the session still works after logout (got %d)", w.Code)
	}
}

// The session cookie must not be readable by scripts or sent cross-site.
func TestSessionCookieFlags(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)
	s.Settings.TLS = true

	cookie, _ := login(t, s, "192.168.1.50", "hunter2hunter2")
	if !cookie.HttpOnly {
		t.Error("the session cookie is readable by scripts")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("the session cookie is not SameSite=Strict")
	}
	if !cookie.Secure {
		t.Error("the session cookie is not Secure under TLS")
	}
}

// Every response carries the security headers, including error responses — a
// 403 that renders as HTML in a browser is still a page.
func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	s := newTestServer(t, &fakeHelper{})
	for _, tc := range []struct{ peer, path string }{
		{"8.8.8.8", "/api/session"},      // refused at gate 1
		{"192.168.1.50", "/api/status"},  // refused at gate 2
		{"192.168.1.50", "/api/session"}, // allowed
	} {
		w := request(t, s, "GET", tc.path, tc.peer, "", nil, nil)
		h := w.Header()
		if !strings.Contains(h.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Errorf("%s from %s has no script-src CSP", tc.path, tc.peer)
		}
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s from %s is missing nosniff", tc.path, tc.peer)
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s from %s can be framed", tc.path, tc.peer)
		}
	}
}

// The CSP must never allow inline or remote scripts. Styles are relaxed because
// the component library sets element styles at runtime; scripts are not.
func TestCSPForbidsInlineAndRemoteScripts(t *testing.T) {
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline'") ||
		strings.Contains(csp, "script-src * ") {
		t.Fatalf("the CSP allows inline or remote scripts: %s", csp)
	}
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("the CSP does not default-deny: %s", csp)
	}
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the CSP allows framing: %s", csp)
	}
}

// An oversized body must be refused rather than buffered: this endpoint accepts
// job scripts, and "generous" and "unlimited" are different things on a box
// with 2 GB of RAM.
func TestOversizedBodyIsRefused(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, csrf := login(t, s, "192.168.1.50", "hunter2hunter2")
	huge := `{"name":"j","schedule":"@daily","script":"` + strings.Repeat("x", 512*1024) + `"}`
	w := request(t, s, "POST", "/api/jobs", "192.168.1.50", huge,
		map[string]string{"X-CSRF-Token": csrf}, []*http.Cookie{cookie})
	if w.Code == http.StatusOK {
		t.Error("a 512 KB body was accepted")
	}
}

// An unknown field is a client bug or an attempt to smuggle a parameter past
// the handler; either way it should not be silently ignored.
func TestUnknownFieldsAreRejected(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, csrf := login(t, s, "192.168.1.50", "hunter2hunter2")
	w := request(t, s, "POST", "/api/clients", "192.168.1.50",
		`{"ip":"192.168.1.9","name":"nas","policy":"proxy","action":"apply"}`,
		map[string]string{"X-CSRF-Token": csrf}, []*http.Cookie{cookie})
	if w.Code == http.StatusOK {
		t.Error("a request carrying an unexpected field was accepted")
	}
}

// The web process must never be the one deciding what is privileged: it
// forwards a named action, and the helper decides.
func TestUnitRestartGoesThroughTheHelperByName(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	cookie, csrf := login(t, s, "192.168.1.50", "hunter2hunter2")
	request(t, s, "POST", "/api/units/xray.service/restart", "192.168.1.50", "",
		map[string]string{"X-CSRF-Token": csrf}, []*http.Cookie{cookie})

	last := helper.calls[len(helper.calls)-1]
	if last.Action != "restart_unit" || last.Unit != "xray.service" {
		t.Errorf("the helper was asked %+v", last)
	}
}
