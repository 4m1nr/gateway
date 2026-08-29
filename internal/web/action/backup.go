package action

import (
	"archive/tar"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/config"
)

// backupVersion is stamped into every archive. A restore refuses anything it
// does not recognise rather than guessing at an older or newer layout.
const backupVersion = 1

// maxBackup bounds both directions. A gateway config is kilobytes; anything
// approaching this is not one.
const maxBackup = 4 << 20

// manifest describes an archive.
type manifest struct {
	Version int       `json:"version"`
	Created time.Time `json:"created"`
	// Host and GwVersion are for the person reading a restore prompt, not for
	// any decision this code makes.
	Host      string   `json:"host"`
	GwVersion string   `json:"gw_version"`
	Files     []string `json:"files"`
	// Secrets records whether outbound credentials are inside. A backup without
	// them restores a gateway that cannot connect, and saying so up front is
	// better than finding out at apply time.
	Secrets bool `json:"secrets"`
}

// backupPaths are what a gateway actually is, relative to the repo.
//
// gateway.toml describes everything, and the outbound files it points at hold
// the credentials. Nothing else is included: the build tree is generated, and
// the dashboard password hash lives outside the repo, 0600 root:root, and is
// deliberately not something this process hands out over HTTP.
//
// The outbounds are found by reading what the config REFERENCES, not by
// listing a conventional directory. `file` may point anywhere, and a backup
// that quietly omitted a credential because it sat outside outbounds/ would
// restore a gateway that cannot connect — and would not say so.
func (h Handler) backupPaths(includeSecrets bool) ([]string, []string, error) {
	if _, err := os.Stat(h.Config); err != nil {
		return nil, nil, fmt.Errorf("there is no config to back up")
	}
	paths := []string{filepath.Base(h.Config)}
	if !includeSecrets {
		return paths, nil, nil
	}

	seen := map[string]bool{paths[0]: true}
	var skipped []string

	add := func(ref string) {
		if ref == "" {
			return
		}
		rel, outside := h.relativeToRepo(ref)
		if outside {
			// Named so the person can see what was left out, rather than
			// discovering it when the restored gateway will not connect.
			skipped = append(skipped, ref)
			return
		}
		if seen[rel] {
			return
		}
		if _, err := os.Stat(filepath.Join(h.Repo, rel)); err != nil {
			return
		}
		seen[rel] = true
		paths = append(paths, rel)
	}

	for _, ref := range h.referencedOutbounds() {
		add(ref)
	}

	// Anything else in outbounds/ as well: a file that is not referenced today
	// is usually one that was, and losing it in a restore is a surprise.
	if entries, err := os.ReadDir(filepath.Join(h.Repo, "outbounds")); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				add(filepath.Join("outbounds", e.Name()))
			}
		}
	}
	return paths, skipped, nil
}

// referencedOutbounds reads every `file` the config points at.
//
// From the raw document rather than the validated config: a config that does
// not currently load still has credentials worth backing up, and that is
// exactly when someone reaches for a backup.
func (h Handler) referencedOutbounds() []string {
	doc, err := h.readDocument()
	if err != nil {
		return nil
	}
	var refs []string

	if xray, ok := doc["xray"].(map[string]any); ok {
		for _, key := range []string{"outbound", "fallback"} {
			if table, ok := xray[key].(map[string]any); ok {
				if file, ok := table["file"].(string); ok {
					refs = append(refs, file)
				}
			}
		}
	}
	if upstreams, ok := doc["upstream"].([]map[string]any); ok {
		for _, u := range upstreams {
			if file, ok := u["file"].(string); ok {
				refs = append(refs, file)
			}
		}
	}
	if upstreams, ok := doc["upstream"].([]any); ok {
		for _, item := range upstreams {
			if u, ok := item.(map[string]any); ok {
				if file, ok := u["file"].(string); ok {
					refs = append(refs, file)
				}
			}
		}
	}
	return refs
}

// relativeToRepo resolves a config-relative reference, reporting whether it
// escapes the repo — a restore can only write inside it.
func (h Handler) relativeToRepo(ref string) (string, bool) {
	full := ref
	if !filepath.IsAbs(full) {
		full = filepath.Join(filepath.Dir(h.Config), ref)
	}
	rel, err := filepath.Rel(h.Repo, full)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", true
	}
	return rel, false
}

// backupCreate returns a gzipped tar of the config, base64 for the JSON
// transport back to the browser.
func (h Handler) backupCreate(req Request) Response {
	includeSecrets := req.Enabled

	paths, skipped, err := h.backupPaths(includeSecrets)
	if err != nil {
		return fail("%v", err)
	}

	var buf strings.Builder
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	gz := gzip.NewWriter(encoder)
	archive := tar.NewWriter(gz)

	host, _ := os.Hostname()
	m := manifest{
		Version: backupVersion,
		Created: time.Now().UTC(),
		Host:    host,
		Files:   paths,
		Secrets: includeSecrets,
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fail("%v", err)
	}
	if err := writeTarFile(archive, "manifest.json", body, 0o600); err != nil {
		return fail("%v", err)
	}

	for _, rel := range paths {
		content, err := os.ReadFile(filepath.Join(h.Repo, rel))
		if err != nil {
			return fail("reading %s: %v", rel, err)
		}
		// 0600 throughout: an outbound holds the credentials that reach the
		// server, and a backup is a file that gets copied to places nobody
		// thought about.
		if err := writeTarFile(archive, rel, content, 0o600); err != nil {
			return fail("%v", err)
		}
	}

	if err := archive.Close(); err != nil {
		return fail("%v", err)
	}
	if err := gz.Close(); err != nil {
		return fail("%v", err)
	}
	if err := encoder.Close(); err != nil {
		return fail("%v", err)
	}

	return ok(map[string]any{
		"filename": fmt.Sprintf("gateway-%s.tar.gz", time.Now().Format("2006-01-02-1504")),
		"archive":  buf.String(),
		"manifest": m,
		"bytes":    len(buf.String()),
		// Outbounds the config points at from outside the repo. They cannot be
		// restored into place, so they are named rather than silently dropped.
		"skipped": skipped,
	})
}

// backupInspect reads an archive without writing anything, so the dashboard can
// show what a restore would do before it does it.
func (h Handler) backupInspect(req Request) Response {
	files, m, err := readArchive(req.JSON)
	if err != nil {
		return fail("%v", err)
	}

	// The config in the archive has to be a config. Validating it here means a
	// restore cannot be the thing that discovers the backup was broken.
	preview := map[string]any{"manifest": m, "files": sortedNames(files)}
	if body, ok := files[filepath.Base(h.Config)]; ok {
		tmp, err := os.CreateTemp(filepath.Dir(h.Config), ".restore-check-*.toml")
		if err == nil {
			defer os.Remove(tmp.Name())
			_, _ = tmp.Write(body)
			tmp.Close()
			if _, err := config.Load(tmp.Name()); err != nil {
				// Not fatal: a config that needs its outbounds restored
				// alongside it will not load on its own, and that is normal.
				preview["config_error"] = err.Error()
			}
		}
		preview["toml"] = string(body)
	} else {
		return fail("this archive has no %s in it", filepath.Base(h.Config))
	}
	return ok(preview)
}

// backupRestore writes an archive back over the config.
//
// The current config and outbounds are backed up first, under one timestamp, so
// a restore of the wrong archive is itself undoable.
func (h Handler) backupRestore(req Request) Response {
	files, m, err := readArchive(req.JSON)
	if err != nil {
		return fail("%v", err)
	}
	configName := filepath.Base(h.Config)
	if _, ok := files[configName]; !ok {
		return fail("this archive has no %s in it", configName)
	}

	stamp := time.Now().Format("20060102-150405")
	for rel, body := range files {
		dest := filepath.Join(h.Repo, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return fail("%v", err)
		}
		// Keep what is being replaced, under one timestamp so the whole
		// restore can be reversed as a set rather than file by file.
		if current, err := os.ReadFile(dest); err == nil {
			_ = os.WriteFile(dest+".before-"+stamp, current, 0o600)
		}
		if err := os.WriteFile(dest, body, 0o600); err != nil {
			return fail("writing %s: %v", rel, err)
		}
	}

	// Now that the outbounds are in place too, the config should load. If it
	// does not, say so plainly — the files are already written, and pretending
	// otherwise would be worse than an honest warning.
	warning := ""
	if _, err := config.Load(h.Config); err != nil {
		warning = "restored, but the config does not load: " + err.Error()
	}

	return Response{
		OK: true,
		Message: fmt.Sprintf("restored %d file(s) from a backup taken %s",
			len(files), m.Created.Local().Format("2006-01-02 15:04")),
		PendingApply: true,
		Data: map[string]any{
			"restored": sortedNames(files),
			"warning":  warning,
			"previous": stamp,
		},
	}
}

// ---------------------------------------------------------------- archive --

func writeTarFile(w *tar.Writer, name string, body []byte, mode int64) error {
	header := &tar.Header{
		Name:    name,
		Mode:    mode,
		Size:    int64(len(body)),
		ModTime: time.Now(),
		Format:  tar.FormatPAX,
	}
	if err := w.WriteHeader(header); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

// readArchive decodes and validates an uploaded backup.
//
// Every entry is checked against path traversal before anything is read. A
// restore writes into the repo as root, so an archive is untrusted input in the
// most literal sense.
func readArchive(encoded string) (map[string][]byte, manifest, error) {
	var m manifest

	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, m, fmt.Errorf("that does not look like a backup file")
	}
	if len(raw) > maxBackup {
		return nil, m, fmt.Errorf("that archive is larger than %d MB, which no gateway "+
			"config is", maxBackup>>20)
	}

	gz, err := gzip.NewReader(strings.NewReader(string(raw)))
	if err != nil {
		return nil, m, fmt.Errorf("that file is not a gzipped archive")
	}
	defer gz.Close()

	files := map[string][]byte{}
	reader := tar.NewReader(io.LimitReader(gz, maxBackup))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, m, fmt.Errorf("the archive is damaged: %w", err)
		}
		if header.Typeflag != tar.TypeReg {
			continue
		}
		name, err := safeName(header.Name)
		if err != nil {
			return nil, m, err
		}
		body, err := io.ReadAll(io.LimitReader(reader, maxBackup))
		if err != nil {
			return nil, m, err
		}
		files[name] = body
	}

	body, ok := files["manifest.json"]
	if !ok {
		return nil, m, fmt.Errorf("this archive has no manifest, so it was not made by gw")
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, m, fmt.Errorf("the archive's manifest is unreadable: %w", err)
	}
	if m.Version != backupVersion {
		return nil, m, fmt.Errorf("this archive is version %d and this gw understands "+
			"version %d", m.Version, backupVersion)
	}
	delete(files, "manifest.json")

	if len(files) == 0 {
		return nil, m, fmt.Errorf("this archive contains no files")
	}
	return files, m, nil
}

// safeName refuses anything that would write outside the repo.
//
// A restore runs as root. "../../etc/sudoers.d/anything" in a tar header is the
// oldest trick there is, and the only safe answer is to reject rather than
// sanitise — a name that needed cleaning was not one gw wrote.
func safeName(name string) (string, error) {
	clean := filepath.Clean(name)
	switch {
	case filepath.IsAbs(clean),
		clean == "..",
		strings.HasPrefix(clean, ".."+string(filepath.Separator)),
		strings.Contains(clean, ".."+string(filepath.Separator)):
		return "", fmt.Errorf("the archive contains a path that would write outside "+
			"the gateway directory (%q), so it was refused entirely", name)
	}
	if clean != name {
		return "", fmt.Errorf("the archive contains a non-canonical path (%q), so it "+
			"was refused entirely", name)
	}
	return clean, nil
}

func sortedNames(files map[string][]byte) []string {
	out := make([]string, 0, len(files))
	for name := range files {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
