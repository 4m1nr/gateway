package web

import (
	"io/fs"
	"net/http"
	"strings"
	"testing"
)

// The dashboard must be embedded in the binary. A build that ships without it
// serves a blank page, and the failure only shows up on the box.
func TestDashboardIsEmbedded(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatalf("no embedded dashboard: %v", err)
	}
	if _, err := fs.Stat(assets, "index.html"); err != nil {
		t.Fatalf("no index.html in the embedded dashboard: %v", err)
	}

	var jsCount, cssCount int
	_ = fs.WalkDir(assets, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".js"):
			jsCount++
		case strings.HasSuffix(p, ".css"):
			cssCount++
		}
		return nil
	})
	if jsCount == 0 || cssCount == 0 {
		t.Errorf("the embedded dashboard has %d JS and %d CSS files — it looks "+
			"like a placeholder rather than a build", jsCount, cssCount)
	}
}

// index.html must reference only same-origin, non-inline scripts, because the
// CSP allows nothing else. A build that inlines the entry chunk would be
// blocked in the browser with no server-side error.
func TestBuiltIndexSatisfiesTheCSP(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if strings.Contains(body, "<script>") && !strings.Contains(body, "<script type=\"module\" src=") {
		t.Error("index.html carries an inline script, which the CSP blocks")
	}
	for _, host := range []string{"http://", "https://", "//cdn."} {
		if strings.Contains(body, `src="`+host) {
			t.Errorf("index.html loads a script from %s, which the CSP blocks", host)
		}
	}
}

func TestStaticServing(t *testing.T) {
	helper := &fakeHelper{password: "hunter2hunter2"}
	s := newTestServer(t, helper)

	// The app itself.
	w := request(t, s, "GET", "/", "192.168.1.50", "", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET / returned %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "<div id=\"root\">") {
		t.Errorf("GET / did not serve the app: %s", truncateStr(w.Body.String(), 200))
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-cache" {
		// index.html must not be cached hard, or a redeploy serves the old app
		// against the new API.
		t.Errorf("index.html Cache-Control is %q, want no-cache", cc)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("the app is served without the CSP")
	}

	// A client-side route must survive a reload rather than 404.
	w = request(t, s, "GET", "/clients", "192.168.1.50", "", nil, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "<div id=\"root\">") {
		t.Errorf("a deep link returned %d; reloading on /clients would 404", w.Code)
	}

	// An unknown API path is a missing endpoint, not a page. Serving the SPA
	// there turns a typo into a confusing HTML body.
	w = request(t, s, "GET", "/api/nonexistent", "192.168.1.50", "", nil, nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("an unknown API path returned %d, want 404", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "json") {
		t.Errorf("an unknown API path returned %s, want JSON", ct)
	}
}

func TestHashedAssetsAreCachedImmutably(t *testing.T) {
	assets, err := Assets()
	if err != nil {
		t.Fatal(err)
	}
	var asset string
	_ = fs.WalkDir(assets, "assets", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && asset == "" {
			asset = p
		}
		return nil
	})
	if asset == "" {
		t.Skip("no hashed assets in this build")
	}

	s := newTestServer(t, &fakeHelper{})
	w := request(t, s, "GET", "/"+asset, "192.168.1.50", "", nil, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /%s returned %d", asset, w.Code)
	}
	if cc := w.Header().Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Errorf("hashed asset Cache-Control is %q, want immutable", cc)
	}
}

// Static assets are behind the address gate like everything else: the dashboard
// should not confirm its own existence to an address that may not use it.
func TestStaticAssetsAreBehindTheAddressGate(t *testing.T) {
	s := newTestServer(t, &fakeHelper{})
	w := request(t, s, "GET", "/", "8.8.8.8", "", nil, nil)
	if w.Code != http.StatusForbidden {
		t.Errorf("the app was served to an address outside allow_cidrs (%d)", w.Code)
	}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
