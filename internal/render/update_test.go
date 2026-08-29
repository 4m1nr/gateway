package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/system"
)

// renderWith renders the default fixture with one setting replaced.
func renderWith(t *testing.T, oldLine, newLine string) []File {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "tests/fixtures/default.toml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	if !strings.Contains(body, oldLine) {
		t.Fatalf("the fixture no longer contains %q", oldLine)
	}
	body = strings.Replace(body, oldLine, newLine, 1)

	// Written beside the fixtures so the outbound's relative `file` path still
	// resolves. A subtest name contains a slash, which would make this a
	// directory that does not exist.
	safe := strings.ReplaceAll(t.Name(), "/", "-")
	path := filepath.Join(root, "tests", "fixtures", ".tmp-"+safe+".toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	files, err := Build(cfg, Options{Repo: root, GeneratedAt: fixedTime})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return files
}

func find(files []File, path string) (File, bool) {
	for _, f := range files {
		if f.Path == path {
			return f, true
		}
	}
	return File{}, false
}

// Geodata had a daily timer; Xray and AdGuard had nothing at all, and updated
// only when somebody remembered to run `gw update` by hand — which is not what
// "auto updates" means to anyone. Each mode must render a timer that runs
// exactly that mode.
func TestAutoUpdateModeReachesTheUnit(t *testing.T) {
	for _, mode := range []string{"check", "services", "all"} {
		t.Run(mode, func(t *testing.T) {
			files := renderWith(t, `auto_update          = "services"`,
				`auto_update          = "`+mode+`"`)
			unit, ok := find(files, "etc/systemd/system/gw-update.service")
			if !ok {
				t.Fatal("no gw-update.service was rendered")
			}
			want := "gw update " + mode
			if !strings.Contains(unit.Content, want) {
				t.Errorf("the unit does not run %q:\n%s", want, unit.Content)
			}
		})
	}
}

// Turning it off must remove the timer, not leave it firing on the old
// schedule while the setting reads as if it worked.
func TestAutoUpdateOffRendersNoTimer(t *testing.T) {
	files := renderWith(t, `auto_update          = "services"`, `auto_update          = "off"`)
	if _, ok := find(files, "etc/systemd/system/gw-update.timer"); ok {
		t.Error(`auto_update = "off" still renders the update timer`)
	}
	if _, ok := find(files, "etc/systemd/system/gw-update.service"); ok {
		t.Error(`auto_update = "off" still renders the update service`)
	}
}

// A unit that stops being rendered must also be one apply knows to remove, or
// turning the feature off leaves it installed and enabled.
func TestUpdateUnitsAreInTheManagedStack(t *testing.T) {
	inStack := false
	for _, u := range system.StackUnits {
		if u == "gw-update.timer" {
			inStack = true
		}
	}
	if !inStack {
		t.Error("gw-update.timer is not in system.StackUnits, so enable and disable ignore it")
	}
}

// The default schedule must be something systemd can actually parse. An
// OnCalendar it cannot parse produces a timer that loads and never fires.
func TestDefaultUpdateScheduleIsRenderedIntoTheTimer(t *testing.T) {
	root := repoRoot(t)
	cfg, err := config.Load(filepath.Join(root, "tests/fixtures/default.toml"))
	if err != nil {
		t.Fatal(err)
	}
	files, err := Build(cfg, Options{Repo: root, GeneratedAt: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	timer, ok := find(files, "etc/systemd/system/gw-update.timer")
	if !ok {
		t.Fatal("no gw-update.timer was rendered")
	}
	if !strings.Contains(timer.Content, "OnCalendar="+cfg.AutoUpdateSchedule) {
		t.Errorf("the timer does not carry the configured schedule %q:\n%s",
			cfg.AutoUpdateSchedule, timer.Content)
	}
}
