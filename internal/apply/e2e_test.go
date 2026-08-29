package apply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/render"
)

var repoRoot = func() string {
	dir, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	return dir
}()

// renderFixture stages a fixture the way `gw render` does.
func renderFixture(t *testing.T, name, stageDir string) []render.File {
	t.Helper()
	cfg, err := config.Load(filepath.Join(repoRoot, "tests/fixtures", name+".toml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	files, err := render.Write(cfg, stageDir, render.Options{Repo: repoRoot})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return files
}

// Applying twice must be a no-op the second time. Without this, `gw diff` after
// an apply reports phantom changes and nobody can tell a real pending edit from
// noise.
func TestApplyIsIdempotent(t *testing.T) {
	(&fakeTools{}).install(t)
	root := t.TempDir()
	stageDir := t.TempDir()

	files := renderFixture(t, "default", stageDir)
	opt := Options{Root: root}

	first, err := Run(Request{Files: files, StageDir: stageDir, Options: opt})
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if !first.Changed() {
		t.Fatal("the first apply onto an empty root reported no changes")
	}

	second, err := Compare(files, opt)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed() {
		t.Errorf("a second apply would still change %d files: %v",
			len(second.Pending()), second.Pending())
	}
}

// Every fixture must install cleanly, with the modes the renderer specified.
func TestEveryFixtureInstalls(t *testing.T) {
	(&fakeTools{}).install(t)
	names, err := filepath.Glob(filepath.Join(repoRoot, "tests/fixtures/*.toml"))
	if err != nil || len(names) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	for _, path := range names {
		name := filepath.Base(path[:len(path)-len(".toml")])
		t.Run(name, func(t *testing.T) {
			root, stageDir := t.TempDir(), t.TempDir()
			files := renderFixture(t, name, stageDir)
			if _, err := Run(Request{Files: files, StageDir: stageDir, Options: Options{Root: root}}); err != nil {
				t.Fatalf("apply: %v", err)
			}
			for _, f := range files {
				if !f.Installed() {
					continue
				}
				st, err := os.Stat(filepath.Join(root, f.Path))
				if err != nil {
					t.Errorf("%s was not installed: %v", f.Path, err)
					continue
				}
				if st.Mode().Perm() != f.Mode.Perm() {
					t.Errorf("%s installed %04o, want %04o", f.Path, st.Mode().Perm(), f.Mode.Perm())
				}
			}
		})
	}
}

// The sudoers fragment must be 0440. sudo refuses a file it considers too
// permissive, and 0644 exposes the grant to every user on the box.
func TestSudoersInstallsRestricted(t *testing.T) {
	(&fakeTools{}).install(t)
	root, stageDir := t.TempDir(), t.TempDir()
	files := renderFixture(t, "default", stageDir)
	if _, err := Run(Request{Files: files, StageDir: stageDir, Options: Options{Root: root}}); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(root, "etc/sudoers.d/gw-web"))
	if err != nil {
		t.Fatalf("the sudoers fragment was not installed: %v", err)
	}
	if st.Mode().Perm() != 0o440 {
		t.Errorf("sudoers installed %04o, want 0440", st.Mode().Perm())
	}
}

// Turning the dashboard off must take its unit and its sudo grant with it.
// Leaving the grant behind means a service user that no longer exists keeps a
// standing NOPASSWD entry.
func TestDisablingTheDashboardRemovesItsUnit(t *testing.T) {
	(&fakeTools{}).install(t)
	root := t.TempDir()

	onDir := t.TempDir()
	on := renderFixture(t, "default", onDir)
	if _, err := Run(Request{Files: on, StageDir: onDir, Options: Options{Root: root}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/gw-web.service")); err != nil {
		t.Fatalf("gw-web.service was not installed to begin with: %v", err)
	}

	offDir := t.TempDir()
	off := renderFixture(t, "no-web", offDir)
	plan, err := Run(Request{Files: off, StageDir: offDir, Options: Options{Root: root}})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Stale) == 0 {
		t.Fatal("disabling the dashboard left gw-web.service in place")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/gw-web.service")); err == nil {
		t.Error("gw-web.service is still installed after web.enabled = false")
	}
}
