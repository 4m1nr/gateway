// Package geodata keeps Xray's routing data current.
//
// Two things make this more than a download loop. It runs unattended, so a
// truncated file or an HTML error page served with a 200 must not reach the
// live config — a bad .dat takes the tunnel down for everyone. And it can draw
// from several sources at once, because no single rule set covers everything
// people actually want to route.
package geodata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/config"
)

// Dir is where Xray reads its .dat files from.
const Dir = "/usr/local/share/xray"

// stampFile records what is installed, per source, so the daily timer is a
// cheap no-op until something upstream actually publishes.
const stampFile = ".releases"

// Updater fetches and installs routing data.
type Updater struct {
	// Dest is the asset directory. Overridden in tests.
	Dest string
	// MinBytes rejects a file smaller than this. A truncated .dat and an error
	// page both land well under a real one.
	MinBytes int64
	// Client fetches. Set in tests; nil means a bounded default.
	Client *http.Client
	// Proxy is the bootstrap SOCKS/HTTP proxy, used only before the tunnel
	// exists.
	Proxy string
	// Now is time.Now, overridable in tests.
	Now func() time.Time
	// Log receives progress.
	Log func(format string, a ...any)
}

// Result is what one source contributed.
type Result struct {
	Source string `json:"source"`
	// Tag identifies the upstream version — a release tag, or a marker for a
	// pinned file set which has no release metadata to compare.
	Tag string `json:"tag"`
	// Installed is what was already present before this run.
	Installed string `json:"installed"`
	// Files are the names this source provided and that were installed.
	Files []string `json:"files"`
	// Skipped are files another source had already provided.
	Skipped []string `json:"skipped"`
	Changed bool     `json:"changed"`
	Error   string   `json:"error,omitempty"`
}

// Report is a whole run.
type Report struct {
	Results []Result `json:"results"`
	// Changed reports whether anything was actually installed.
	Changed bool `json:"changed"`
	// Failed counts sources that could not be read.
	Failed int `json:"failed"`
}

func (u Updater) dest() string {
	if u.Dest != "" {
		return u.Dest
	}
	return Dir
}

func (u Updater) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u Updater) logf(format string, a ...any) {
	if u.Log != nil {
		u.Log(format, a...)
	}
}

// client returns the HTTP client, honouring the bootstrap proxy.
//
// The proxy matters only before the tunnel exists: once the gateway carries its
// own traffic the output chain routes this like anything else.
func (u Updater) client() (*http.Client, error) {
	if u.Client != nil {
		return u.Client, nil
	}
	transport := &http.Transport{}
	if u.Proxy != "" {
		parsed, err := url.Parse(u.Proxy)
		if err != nil {
			return nil, fmt.Errorf("bootstrap.socks_proxy %q is not a URL: %w", u.Proxy, err)
		}
		transport.Proxy = http.ProxyURL(parsed)
	}
	// Generous but bounded: a .dat is tens of megabytes over a slow tunnel, and
	// an unbounded download is how an unattended timer runs until next week.
	return &http.Client{Transport: transport, Timeout: 10 * time.Minute}, nil
}

// Check reports what each source offers, changing nothing.
func (u Updater) Check(ctx context.Context, sources []config.GeoSource) Report {
	installed := u.readStamps()
	var report Report
	for _, source := range sources {
		if !source.Enabled {
			continue
		}
		result := Result{Source: source.Name, Installed: installed[source.Name]}
		tag, _, err := u.resolve(ctx, source)
		if err != nil {
			result.Error = err.Error()
			report.Failed++
		} else {
			result.Tag = tag
			result.Changed = tag != result.Installed
		}
		if result.Changed {
			report.Changed = true
		}
		report.Results = append(report.Results, result)
	}
	return report
}

// Update fetches everything that changed and installs it.
//
// Every file is downloaded and size-checked before ANY of them is installed,
// and the previous set is kept until Xray has accepted the new one. A rule file
// that arrives truncated must not be able to take the tunnel down.
func (u Updater) Update(ctx context.Context, sources []config.GeoSource, force bool) (Report, error) {
	installed := u.readStamps()
	updated := map[string]string{}
	for k, v := range installed {
		updated[k] = v
	}

	// Staged first, keyed by file name. First source to provide a name wins,
	// matching how everything else here resolves.
	staged := map[string][]byte{}
	provider := map[string]string{}

	var report Report
	for _, source := range sources {
		if !source.Enabled {
			continue
		}
		result := Result{Source: source.Name, Installed: installed[source.Name]}

		tag, urls, err := u.resolve(ctx, source)
		if err != nil {
			result.Error = err.Error()
			report.Failed++
			report.Results = append(report.Results, result)
			continue
		}
		result.Tag = tag

		if tag == result.Installed && !force {
			u.logf("%s: already at %s", source.Name, tag)
			report.Results = append(report.Results, result)
			continue
		}

		for _, link := range urls {
			name := filepath.Base(link)
			if owner, taken := provider[name]; taken {
				// Reported rather than silently dropped: two sources shipping
				// geoip.dat is a real thing to want to know about.
				result.Skipped = append(result.Skipped, name+" (already from "+owner+")")
				continue
			}
			body, err := u.fetch(ctx, link)
			if err != nil {
				result.Error = err.Error()
				report.Failed++
				break
			}
			staged[name] = body
			provider[name] = source.Name
			result.Files = append(result.Files, name)
			u.logf("    %s (%d bytes) from %s", name, len(body), source.Name)
		}

		if result.Error == "" && len(result.Files) > 0 {
			result.Changed = true
			report.Changed = true
			updated[source.Name] = tag
		}
		report.Results = append(report.Results, result)
	}

	if !report.Changed {
		return report, nil
	}
	if err := u.install(staged); err != nil {
		return report, err
	}
	if err := u.writeStamps(updated); err != nil {
		return report, err
	}
	return report, nil
}

// resolve works out the version and the file URLs for one source.
func (u Updater) resolve(ctx context.Context, source config.GeoSource) (string, []string, error) {
	if len(source.Files) > 0 {
		template := source.URLTemplate
		if template == "" {
			// A pinned set against a repo uses the release's download path.
			template = "https://github.com/" + source.Repo + "/releases/latest/download/{0}.dat"
		}
		var urls []string
		for _, name := range source.Files {
			urls = append(urls, strings.ReplaceAll(template, "{0}", name))
		}
		// A pinned set has no release metadata to compare, so its identity is
		// the set itself: changing the list is what makes it re-fetch.
		return "pinned:" + strings.Join(source.Files, ","), urls, nil
	}

	if source.Repo == "" {
		return "", nil, fmt.Errorf("no repo and no files")
	}
	return u.latestRelease(ctx, source.Repo)
}

// latestRelease reads a GitHub release and returns its tag and every .dat asset.
func (u Updater) latestRelease(ctx context.Context, repo string) (string, []string, error) {
	body, err := u.fetch(ctx, "https://api.github.com/repos/"+repo+"/releases/latest")
	if err != nil {
		return "", nil, fmt.Errorf("could not read the latest release of %s: %w\n"+
			"If this box has no direct internet yet, set bootstrap.socks_proxy.", repo, err)
	}
	var release struct {
		Tag    string `json:"tag_name"`
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &release); err != nil {
		return "", nil, fmt.Errorf("could not parse the release response from %s: %w", repo, err)
	}
	var urls []string
	for _, asset := range release.Assets {
		if strings.HasSuffix(asset.Name, ".dat") {
			urls = append(urls, asset.URL)
		}
	}
	if release.Tag == "" || len(urls) == 0 {
		return "", nil, fmt.Errorf("the latest release of %s has no tag or no .dat assets", repo)
	}
	sort.Strings(urls)
	return release.Tag, urls, nil
}

// fetch downloads one URL, refusing anything implausibly small.
func (u Updater) fetch(ctx context.Context, link string) ([]byte, error) {
	client, err := u.client()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream, application/json")
	req.Header.Set("User-Agent", "gw-geoupdate")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", link, resp.Status)
	}

	// Bounded read: a redirect to something enormous should not fill the disk
	// of a box whose whole storage is a flash module.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", link, err)
	}

	// The size check is the one that matters. A truncated transfer and an HTML
	// error page served with a 200 both land far below a real rule file, and
	// both would take the tunnel down at the next Xray restart.
	if strings.HasSuffix(link, ".dat") && int64(len(body)) < u.minBytes() {
		return nil, fmt.Errorf("%s is only %d bytes (minimum %d) — refusing it",
			filepath.Base(link), len(body), u.minBytes())
	}
	return body, nil
}

func (u Updater) minBytes() int64 {
	if u.MinBytes > 0 {
		return u.MinBytes
	}
	return 102400
}

// install writes the staged files, keeping the previous set until Xray has
// accepted them.
func (u Updater) install(staged map[string][]byte) error {
	dest := u.dest()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}

	backup := map[string][]byte{}
	for name := range staged {
		if current, err := os.ReadFile(filepath.Join(dest, name)); err == nil {
			backup[name] = current
		}
	}

	for name, body := range staged {
		if err := os.WriteFile(filepath.Join(dest, name), body, 0o644); err != nil {
			u.rollback(backup)
			return fmt.Errorf("installing %s: %w", name, err)
		}
	}

	// On a first install there is no config and no service yet — fetching is
	// the whole job at that point.
	if _, err := os.Stat(XrayConfig); err != nil {
		return nil
	}
	if err := u.validate(); err != nil {
		u.logf("xray rejects the new geodata, rolling back")
		u.rollback(backup)
		return err
	}
	return nil
}

// XrayConfig is the live config the new data is tested against.
var XrayConfig = "/usr/local/etc/xray/config.json"

// Validate is the hook the test suite replaces; production runs xray -test.
var Validate func() error

func (u Updater) validate() error {
	if Validate != nil {
		return Validate()
	}
	return runXrayTest()
}

func (u Updater) rollback(backup map[string][]byte) {
	for name, body := range backup {
		_ = os.WriteFile(filepath.Join(u.dest(), name), body, 0o644)
	}
}

// ---------------------------------------------------------------- stamps --

// readStamps reads what is installed per source.
func (u Updater) readStamps() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(filepath.Join(u.dest(), stampFile))
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

func (u Updater) writeStamps(stamps map[string]string) error {
	body, err := json.MarshalIndent(stamps, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(u.dest(), stampFile), append(body, '\n'), 0o644)
}
