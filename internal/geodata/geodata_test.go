package geodata

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/config"
)

// fakeUpstream serves release metadata and .dat files.
type fakeUpstream struct {
	*httptest.Server
	// tag is the release tag it reports; change it to simulate a publish.
	tag string
	// size is how many bytes each .dat is.
	size int
	// hits counts downloads, to prove a no-op run downloads nothing.
	hits int
}

func newUpstream(t *testing.T, tag string, assets []string) *fakeUpstream {
	t.Helper()
	up := &fakeUpstream{tag: tag, size: 200000}
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		type asset struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}
		var list []asset
		for _, name := range assets {
			list = append(list, asset{Name: name, URL: up.URL + "/dl/" + name})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tag_name": up.tag, "assets": list,
		})
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		up.hits++
		_, _ = w.Write(make([]byte, up.size))
	})

	up.Server = httptest.NewServer(mux)
	t.Cleanup(up.Close)
	return up
}

// updater builds one pointed at a temp directory and the fake upstream.
func updater(t *testing.T, up *fakeUpstream) Updater {
	t.Helper()
	// No xray on a test machine; the validation hook stands in for it.
	old := Validate
	Validate = func() error { return nil }
	t.Cleanup(func() { Validate = old })

	return Updater{
		Dest:     t.TempDir(),
		MinBytes: 102400,
		Client:   up.Client(),
		Log:      func(string, ...any) {},
	}
}

// source builds a config source pointed at the fake upstream's API.
func source(name, repo string, up *fakeUpstream, files ...string) config.GeoSource {
	s := config.GeoSource{Name: name, Repo: repo, Enabled: true, Files: files}
	if len(files) > 0 {
		s.URLTemplate = up.URL + "/dl/{0}.dat"
	}
	return s
}

// rewriteAPI points the updater at the test server instead of GitHub.
func rewriteAPI(t *testing.T, u Updater, up *fakeUpstream) Updater {
	t.Helper()
	u.Client = &http.Client{Transport: rewriter{base: up.URL, inner: up.Client().Transport}}
	return u
}

type rewriter struct {
	base  string
	inner http.RoundTripper
}

func (r rewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasPrefix(req.URL.String(), "https://api.github.com") {
		rewritten := r.base + strings.TrimPrefix(req.URL.String(), "https://api.github.com")
		parsed, err := req.URL.Parse(rewritten)
		if err != nil {
			return nil, err
		}
		req = req.Clone(req.Context())
		req.URL = parsed
		req.Host = parsed.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func TestUpdateInstallsFromARelease(t *testing.T) {
	up := newUpstream(t, "v1", []string{"geoip.dat", "geosite.dat"})
	u := rewriteAPI(t, updater(t, up), up)

	report, err := u.Update(context.Background(), []config.GeoSource{
		source("iran", "someone/rules", up),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Changed || report.Failed != 0 {
		t.Fatalf("report: %+v", report)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if _, err := os.Stat(filepath.Join(u.Dest, name)); err != nil {
			t.Errorf("%s was not installed: %v", name, err)
		}
	}
}

// The daily timer must be a cheap no-op until upstream actually publishes.
func TestNoOpWhenNothingChanged(t *testing.T) {
	up := newUpstream(t, "v1", []string{"geoip.dat"})
	u := rewriteAPI(t, updater(t, up), up)
	src := []config.GeoSource{source("iran", "someone/rules", up)}

	if _, err := u.Update(context.Background(), src, false); err != nil {
		t.Fatal(err)
	}
	downloads := up.hits

	report, err := u.Update(context.Background(), src, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed {
		t.Error("a second run with no upstream change reported a change")
	}
	if up.hits != downloads {
		t.Errorf("a no-op run downloaded %d file(s)", up.hits-downloads)
	}

	// And it does fetch again once the tag moves.
	up.tag = "v2"
	report, err = u.Update(context.Background(), src, false)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Changed {
		t.Error("a new upstream release was not picked up")
	}
}

// The point of the feature: several sources, each tracked separately.
func TestMultipleSourcesAreTrackedIndependently(t *testing.T) {
	first := newUpstream(t, "a1", []string{"geoip.dat", "geosite.dat"})
	second := newUpstream(t, "b1", []string{"extra.dat"})

	u := updater(t, first)
	u.Client = &http.Client{Transport: rewriter{base: first.URL}}

	sources := []config.GeoSource{
		source("first", "one/rules", first),
		// The second is reached by template, so it needs no API rewrite.
		{Name: "second", Enabled: true, Files: []string{"extra"},
			URLTemplate: second.URL + "/dl/{0}.dat"},
	}

	report, err := u.Update(context.Background(), sources, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 0 {
		t.Fatalf("a source failed: %+v", report.Results)
	}
	for _, name := range []string{"geoip.dat", "geosite.dat", "extra.dat"} {
		if _, err := os.Stat(filepath.Join(u.Dest, name)); err != nil {
			t.Errorf("%s from a second source was not installed: %v", name, err)
		}
	}
	if len(report.Results) != 2 {
		t.Fatalf("expected a result per source, got %d", len(report.Results))
	}
}

// Two sources shipping geoip.dat is a real situation. First wins, and the
// second says so rather than silently losing.
func TestFirstSourceWinsAndTheClashIsReported(t *testing.T) {
	first := newUpstream(t, "a1", []string{"geoip.dat"})
	second := newUpstream(t, "b1", []string{"geoip.dat"})
	first.size = 300000
	second.size = 400000

	u := updater(t, first)
	u.Client = &http.Client{Transport: rewriter{base: first.URL}}

	report, err := u.Update(context.Background(), []config.GeoSource{
		{Name: "primary", Enabled: true, Files: []string{"geoip"},
			URLTemplate: first.URL + "/dl/{0}.dat"},
		{Name: "secondary", Enabled: true, Files: []string{"geoip"},
			URLTemplate: second.URL + "/dl/{0}.dat"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(u.Dest, "geoip.dat"))
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != 300000 {
		t.Errorf("the file came from the wrong source: %d bytes", len(body))
	}
	var skipped []string
	for _, r := range report.Results {
		skipped = append(skipped, r.Skipped...)
	}
	if len(skipped) == 0 {
		t.Error("the clash was not reported, so it would be invisible")
	}
}

// The check that stops a bad download taking the tunnel down. A truncated file
// and an HTML error page served with a 200 both land far below a real one.
func TestUndersizedFileIsRefused(t *testing.T) {
	up := newUpstream(t, "v1", []string{"geoip.dat"})
	up.size = 500 // an error page, not a rule file
	u := rewriteAPI(t, updater(t, up), up)

	report, err := u.Update(context.Background(), []config.GeoSource{
		source("iran", "someone/rules", up),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed == 0 {
		t.Fatal("a 500-byte .dat was accepted")
	}
	if _, err := os.Stat(filepath.Join(u.Dest, "geoip.dat")); err == nil {
		t.Error("the undersized file was installed anyway")
	}
}

// If Xray rejects the new data, the previous set must come back — the whole
// point of testing before committing to it.
func TestRollbackWhenXrayRejectsTheNewData(t *testing.T) {
	up := newUpstream(t, "v1", []string{"geoip.dat"})
	u := updater(t, up)
	u.Client = &http.Client{Transport: rewriter{base: up.URL}}

	// An existing file, and a config for the validator to be asked about.
	existing := []byte("the previous rule data")
	if err := os.WriteFile(filepath.Join(u.Dest, "geoip.dat"), existing, 0o644); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(configPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldConfig := XrayConfig
	XrayConfig = configPath
	t.Cleanup(func() { XrayConfig = oldConfig })

	Validate = func() error { return errAlwaysRejects }

	_, err := u.Update(context.Background(), []config.GeoSource{
		{Name: "iran", Enabled: true, Files: []string{"geoip"},
			URLTemplate: up.URL + "/dl/{0}.dat"},
	}, false)
	if err == nil {
		t.Fatal("data Xray rejected was accepted")
	}

	body, readErr := os.ReadFile(filepath.Join(u.Dest, "geoip.dat"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != string(existing) {
		t.Error("the previous geodata was not restored after Xray rejected the new set")
	}
}

var errAlwaysRejects = &rejectError{}

type rejectError struct{}

func (e *rejectError) Error() string { return "xray rejected the new geodata" }

// A disabled source is kept in the config and skipped.
func TestDisabledSourceIsSkipped(t *testing.T) {
	up := newUpstream(t, "v1", []string{"geoip.dat"})
	u := rewriteAPI(t, updater(t, up), up)

	report, err := u.Update(context.Background(), []config.GeoSource{
		{Name: "off", Enabled: false, Repo: "someone/rules"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed || len(report.Results) != 0 {
		t.Errorf("a disabled source was used: %+v", report)
	}
	if up.hits != 0 {
		t.Error("a disabled source was downloaded from")
	}
}

// Check reports without touching anything.
func TestCheckChangesNothing(t *testing.T) {
	up := newUpstream(t, "v1", []string{"geoip.dat"})
	u := rewriteAPI(t, updater(t, up), up)
	src := []config.GeoSource{source("iran", "someone/rules", up)}

	report := u.Check(context.Background(), src)
	if !report.Changed {
		t.Error("an uninstalled source was not reported as an available update")
	}
	if entries, _ := os.ReadDir(u.Dest); len(entries) != 0 {
		t.Errorf("check wrote %d file(s)", len(entries))
	}
}

// One unreachable source must not stop the others.
func TestOneFailingSourceDoesNotStopTheRest(t *testing.T) {
	good := newUpstream(t, "v1", []string{"geoip.dat"})
	u := updater(t, good)
	u.Client = &http.Client{Transport: rewriter{base: good.URL}}

	report, err := u.Update(context.Background(), []config.GeoSource{
		{Name: "broken", Enabled: true, Files: []string{"geoip"},
			URLTemplate: "http://127.0.0.1:1/{0}.dat"},
		{Name: "working", Enabled: true, Files: []string{"geoip"},
			URLTemplate: good.URL + "/dl/{0}.dat"},
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Failed != 1 {
		t.Errorf("expected exactly one failure, got %d", report.Failed)
	}
	if !report.Changed {
		t.Error("the working source did not install anything")
	}
	if _, err := os.Stat(filepath.Join(u.Dest, "geoip.dat")); err != nil {
		t.Errorf("the working source's file is missing: %v", err)
	}
}
