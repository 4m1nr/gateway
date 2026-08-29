package adguard

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func load(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := yaml.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// AdGuard's own settings — the admin password hash above all — must survive.
// Losing them means the owner is locked out of their resolver by a `gw apply`.
func TestMergeKeepsWhatAdGuardOwns(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "AdGuardHome.yaml", `
schema_version: 29
users:
  - name: admin
    password: $2a$10$SOMEBCRYPTHASH
http:
  address: 0.0.0.0:3000
  session_ttl: 720h
dns:
  port: 53
  upstream_dns:
    - 8.8.8.8
  ratelimit: 20
  something_adguard_added: true
`)

	err := Merge(path, map[string]any{
		"dns": map[string]any{
			"port":         53,
			"upstream_dns": []any{"[/ir/]1.1.1.1", "https://1.1.1.1/dns-query"},
			"ratelimit":    0,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := load(t, path)
	if got["schema_version"] != 29 {
		t.Error("schema_version was lost")
	}
	users, _ := got["users"].([]any)
	if len(users) != 1 {
		t.Fatal("the users list was lost — the owner is locked out of AdGuard")
	}

	dns, _ := asMap(got["dns"])
	if dns["something_adguard_added"] != true {
		t.Error("a key AdGuard set itself was dropped")
	}
	if dns["ratelimit"] != 0 {
		t.Errorf("ratelimit is %v, want 0", dns["ratelimit"])
	}

	// Lists are replaced, not appended: a merged upstream list would mix old
	// resolvers with new and produce a set nobody chose.
	up, _ := dns["upstream_dns"].([]any)
	if len(up) != 2 || up[0] != "[/ir/]1.1.1.1" {
		t.Errorf("upstream_dns is %v, want exactly the two new entries", up)
	}

	// Nested maps outside the overlay are untouched.
	httpSec, _ := asMap(got["http"])
	if httpSec["session_ttl"] != "720h" {
		t.Errorf("http.session_ttl is %v, want 720h", httpSec["session_ttl"])
	}
}

func TestMergeWritesABackupBeforeChangingAnything(t *testing.T) {
	dir := t.TempDir()
	original := "dns:\n  port: 53\n"
	path := write(t, dir, "AdGuardHome.yaml", original)

	if err := Merge(path, map[string]any{"dns": map[string]any{"port": 5353}}); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(path + ".bak")
	if err != nil {
		t.Fatalf("no backup was written: %v", err)
	}
	if string(backup) != original {
		t.Errorf("the backup is not the original file:\n%s", backup)
	}
}

// The file holds a password hash, so its permissions must not be widened.
func TestMergePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "AdGuardHome.yaml", "dns:\n  port: 53\n")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Merge(path, map[string]any{"dns": map[string]any{"port": 5353}}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("permissions became %04o, want 0600", st.Mode().Perm())
	}
}

// A box where AdGuard has never been started must say so, rather than writing a
// config that AdGuard will then overwrite or reject.
func TestMergeExplainsAMissingFile(t *testing.T) {
	err := Merge(filepath.Join(t.TempDir(), "AdGuardHome.yaml"), map[string]any{})
	if err == nil {
		t.Fatal("merging into a missing file reported success")
	}
	if want := "start AdGuard Home once"; !contains(err.Error(), want) {
		t.Errorf("the error does not explain what to do: %v", err)
	}
}

func TestMergeRefusesInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := write(t, dir, "AdGuardHome.yaml", "dns:\n  port: [unclosed\n")
	if err := Merge(path, map[string]any{}); err == nil {
		t.Fatal("invalid YAML was accepted")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
