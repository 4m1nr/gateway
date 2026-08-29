package action

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupRoundTrip(t *testing.T) {
	h := newHandler(t)

	created := h.Handle(Request{Action: "backup_create", Enabled: true})
	if !created.OK {
		t.Fatalf("%s", created.Error)
	}
	archive, _ := created.Data["archive"].(string)
	if archive == "" {
		t.Fatal("no archive was produced")
	}

	// Change the config, then restore over it.
	if err := os.WriteFile(h.Config, []byte("[net]\nwan_if = \"changed\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored := h.Handle(Request{Action: "backup_restore", JSON: archive})
	if !restored.OK {
		t.Fatalf("%s", restored.Error)
	}

	body, err := os.ReadFile(h.Config)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "192.168.1.0/24") {
		t.Errorf("the config was not restored:\n%s", body)
	}
	if warning, _ := restored.Data["warning"].(string); warning != "" {
		t.Errorf("the restored config does not load: %s", warning)
	}
}

// A restore of the wrong archive has to be undoable: the files it replaces are
// kept under one timestamp so the whole thing reverses as a set.
func TestRestoreKeepsWhatItReplaced(t *testing.T) {
	h := newHandler(t)
	created := h.Handle(Request{Action: "backup_create", Enabled: true})
	archive, _ := created.Data["archive"].(string)

	marker := "[net]\nwan_if = \"about-to-be-replaced\"\n"
	if err := os.WriteFile(h.Config, []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	restored := h.Handle(Request{Action: "backup_restore", JSON: archive})
	if !restored.OK {
		t.Fatalf("%s", restored.Error)
	}
	stamp, _ := restored.Data["previous"].(string)
	if stamp == "" {
		t.Fatal("no timestamp was reported, so the previous files cannot be found")
	}

	kept, err := os.ReadFile(h.Config + ".before-" + stamp)
	if err != nil {
		t.Fatalf("the replaced config was not kept: %v", err)
	}
	if string(kept) != marker {
		t.Error("what was kept is not what was replaced")
	}
}

// Credentials are the reason a backup is sensitive. Leaving them out has to be
// possible, and the archive has to say which kind it is.
func TestBackupCanExcludeCredentials(t *testing.T) {
	h := newHandler(t)

	with := h.Handle(Request{Action: "backup_create", Enabled: true})
	without := h.Handle(Request{Action: "backup_create", Enabled: false})
	if !with.OK || !without.OK {
		t.Fatalf("%s %s", with.Error, without.Error)
	}

	withFiles, withManifest, err := readArchive(with.Data["archive"].(string))
	if err != nil {
		t.Fatal(err)
	}
	withoutFiles, withoutManifest, err := readArchive(without.Data["archive"].(string))
	if err != nil {
		t.Fatal(err)
	}

	if !withManifest.Secrets || withoutManifest.Secrets {
		t.Errorf("the manifest does not record which kind it is: %v / %v",
			withManifest.Secrets, withoutManifest.Secrets)
	}
	hasOutbound := func(files map[string][]byte) bool {
		for name := range files {
			if strings.HasPrefix(name, "outbounds/") {
				return true
			}
		}
		return false
	}
	if !hasOutbound(withFiles) {
		t.Error("a backup with credentials has no outbounds in it")
	}
	if hasOutbound(withoutFiles) {
		t.Error("a backup without credentials still carries an outbound")
	}
}

// A restore runs as root and writes into the repo. An archive is untrusted
// input in the most literal sense.
func TestRestoreRefusesPathTraversal(t *testing.T) {
	for _, name := range []string{
		"../../etc/sudoers.d/evil",
		"/etc/passwd",
		"outbounds/../../../root/.ssh/authorized_keys",
		"./../gateway.toml",
	} {
		archive := buildArchive(t, map[string]string{
			"manifest.json": `{"version":1,"files":["gateway.toml"]}`,
			"gateway.toml":  "[net]\n",
			name:            "owned",
		})
		h := newHandler(t)
		resp := h.Handle(Request{Action: "backup_restore", JSON: archive})
		if resp.OK {
			t.Errorf("an archive containing %q was restored", name)
			continue
		}
		if !strings.Contains(resp.Error, "refused") {
			t.Errorf("the refusal for %q does not say it was refused: %s", name, resp.Error)
		}
	}
}

// A refused archive must leave nothing behind — not a partial restore of the
// entries that looked fine before the bad one.
func TestARefusedArchiveWritesNothing(t *testing.T) {
	h := newHandler(t)
	before, _ := os.ReadFile(h.Config)

	archive := buildArchive(t, map[string]string{
		"manifest.json":  `{"version":1,"files":["gateway.toml"]}`,
		"gateway.toml":   "[net]\nwan_if = \"replaced\"\n",
		"../escaped.txt": "x",
	})
	if resp := h.Handle(Request{Action: "backup_restore", JSON: archive}); resp.OK {
		t.Fatal("the archive was restored")
	}
	after, _ := os.ReadFile(h.Config)
	if string(before) != string(after) {
		t.Error("the config was modified by a refused restore")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(h.Repo), "escaped.txt")); err == nil {
		t.Error("a file was written outside the repo")
	}
}

func TestRestoreRefusesNonsense(t *testing.T) {
	h := newHandler(t)
	for _, body := range []string{
		"", "not base64", base64.StdEncoding.EncodeToString([]byte("not a gzip")),
	} {
		if resp := h.Handle(Request{Action: "backup_restore", JSON: body}); resp.OK {
			t.Errorf("%q was accepted as a backup", body)
		}
	}

	// A valid archive from a future version must be refused, not guessed at.
	future := buildArchive(t, map[string]string{
		"manifest.json": `{"version":99}`,
		"gateway.toml":  "[net]\n",
	})
	resp := h.Handle(Request{Action: "backup_restore", JSON: future})
	if resp.OK {
		t.Error("an archive from a future version was restored")
	}
	if !strings.Contains(resp.Error, "version") {
		t.Errorf("the refusal does not mention the version: %s", resp.Error)
	}

	// And one with no config in it is not a gateway backup.
	empty := buildArchive(t, map[string]string{
		"manifest.json":    `{"version":1}`,
		"outbounds/x.json": "{}",
	})
	if resp := h.Handle(Request{Action: "backup_restore", JSON: empty}); resp.OK {
		t.Error("an archive with no gateway.toml was restored")
	}
}

// Inspecting must write nothing: it exists so a restore can be reviewed first.
func TestInspectWritesNothing(t *testing.T) {
	h := newHandler(t)
	created := h.Handle(Request{Action: "backup_create", Enabled: true})
	archive, _ := created.Data["archive"].(string)

	before, _ := os.ReadFile(h.Config)
	resp := h.Handle(Request{Action: "backup_inspect", JSON: archive})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	if body, _ := resp.Data["toml"].(string); !strings.Contains(body, "[net]") {
		t.Error("inspect did not return the config it would restore")
	}
	after, _ := os.ReadFile(h.Config)
	if string(before) != string(after) {
		t.Error("inspect modified the config")
	}
}

// buildArchive makes a tar.gz with arbitrary entry names, including ones a
// well-behaved writer would never produce.
func buildArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	var raw bytes.Buffer
	gz := gzip.NewWriter(&raw)
	w := tar.NewWriter(gz)
	for name, body := range files {
		if err := w.WriteHeader(&tar.Header{
			Name: name, Mode: 0o600, Size: int64(len(body)),
			ModTime: time.Now(), Format: tar.FormatPAX,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	w.Close()
	gz.Close()
	return base64.StdEncoding.EncodeToString(raw.Bytes())
}
