package apply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/am1nr/gateway/internal/render"
)

func files(entries ...render.File) []render.File { return entries }

func f(path, content string, mode os.FileMode) render.File {
	return render.File{Path: path, Content: content, Mode: mode}
}

func TestCompareClassifiesFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "etc/same"), "hello\n")
	mustWrite(t, filepath.Join(root, "etc/differs"), "old\n")

	plan, err := Compare(files(
		f("etc/same", "hello\n", 0o644),
		f("etc/differs", "new\n", 0o644),
		f("etc/absent", "fresh\n", 0o644),
	), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}

	got := map[string]Status{}
	for _, c := range plan.Changes {
		got[c.Path] = c.Status
	}
	want := map[string]Status{
		"etc/same": Unchanged, "etc/differs": Changed, "etc/absent": New,
	}
	for path, w := range want {
		if got[path] != w {
			t.Errorf("%s is %q, want %q", path, got[path], w)
		}
	}
	if !plan.Changed() {
		t.Error("plan reports no changes but two files differ")
	}
	if n := len(plan.Pending()); n != 2 {
		t.Errorf("Pending returned %d changes, want 2", n)
	}
}

// The staging tree holds two entries apply consumes directly. Installing them
// would litter the filesystem root with files nothing reads.
func TestNonFilesystemEntriesAreNotInstalled(t *testing.T) {
	root := t.TempDir()
	plan, err := Compare(files(
		f("adguard-overrides.json", "{}\n", 0o644),
		f("tailscale-args", "--ssh\n", 0o644),
		f("etc/real", "x\n", 0o644),
	), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Changes) != 1 || plan.Changes[0].Path != "etc/real" {
		t.Errorf("expected only etc/real in the plan, got %+v", plan.Changes)
	}

	if _, err := Install(files(
		f("adguard-overrides.json", "{}\n", 0o644),
		f("etc/real", "x\n", 0o644),
	), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "adguard-overrides.json")); err == nil {
		t.Error("adguard-overrides.json was installed onto the filesystem")
	}
}

// Turning a feature off must remove its unit. Leaving it behind means the timer
// stays enabled and keeps firing on the old schedule, so the setting looks like
// it worked and changed nothing.
func TestStaleUnitsAreDetectedAndRemoved(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "etc/systemd/system/gw-update.timer"), "[Timer]\n")
	mustWrite(t, filepath.Join(root, "etc/systemd/system/gw-web.service"), "[Service]\n")

	plan, err := Compare(files(
		f("etc/systemd/system/gw-web.service", "[Service]\n", 0o644),
	), Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Stale) != 1 || plan.Stale[0] != "etc/systemd/system/gw-update.timer" {
		t.Fatalf("stale units are %v, want just the update timer", plan.Stale)
	}
	if !plan.Changed() {
		t.Error("a stale unit alone should count as a change")
	}
	if err := RemoveStale(plan, Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/gw-update.timer")); err == nil {
		t.Error("the stale timer is still installed")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/gw-web.service")); err != nil {
		t.Error("a unit that is still rendered was removed")
	}
}

// Modes come from the renderer, not the umask. A job script that installs 0755
// is world-readable and they run as root and may hold credentials; a sudoers
// fragment that is not 0440 makes sudo refuse to run at all.
func TestInstallAppliesModesExactly(t *testing.T) {
	root := t.TempDir()
	if _, err := Install(files(
		f("usr/local/lib/gateway/jobs/backup.sh", "#!/bin/bash\n", 0o700),
		f("etc/sudoers.d/gw-web", "gwweb ALL=(root) NOPASSWD: /x\n", 0o440),
		f("etc/gateway/web.json", "{}\n", 0o644),
	), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{
		"usr/local/lib/gateway/jobs/backup.sh": 0o700,
		"etc/sudoers.d/gw-web":                 0o440,
		"etc/gateway/web.json":                 0o644,
	} {
		st, err := os.Stat(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s installed %04o, want %04o", path, st.Mode().Perm(), want)
		}
	}
}

// Overwriting an existing file must also reset its mode: a job script that was
// 0755 before must not stay 0755 after.
func TestInstallResetsModeOnOverwrite(t *testing.T) {
	root := t.TempDir()
	path := "usr/local/lib/gateway/jobs/backup.sh"
	mustWrite(t, filepath.Join(root, path), "#!/bin/bash\nold\n")
	if err := os.Chmod(filepath.Join(root, path), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(files(f(path, "#!/bin/bash\nnew\n", 0o700)), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(root, path))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o700 {
		t.Errorf("mode is %04o after overwrite, want 0700", st.Mode().Perm())
	}
}

// A half-written ruleset is worse than an old one: the service that reads it
// next fails to start. Nothing may be left behind under the target name.
func TestInstallLeavesNoTempFiles(t *testing.T) {
	root := t.TempDir()
	if _, err := Install(files(f("etc/nftables.d/gateway.nft", "table x {}\n", 0o644)), Options{Root: root}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, "etc/nftables.d"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "gateway.nft" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory holds %v, want only gateway.nft", names)
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
