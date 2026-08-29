package apply

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordingSystem logs every system call in order.
type recordingSystem struct{ calls []string }

func (s *recordingSystem) EnsureUser(n string) error {
	s.calls = append(s.calls, "user:"+n)
	return nil
}
func (s *recordingSystem) SysctlReload() error { s.calls = append(s.calls, "sysctl"); return nil }
func (s *recordingSystem) DaemonReload() error {
	s.calls = append(s.calls, "daemon-reload")
	return nil
}
func (s *recordingSystem) Restart(u string) error {
	s.calls = append(s.calls, "restart:"+u)
	return nil
}
func (s *recordingSystem) Disable(u string) error {
	s.calls = append(s.calls, "disable:"+u)
	return nil
}
func (s *recordingSystem) EnableStack() error { s.calls = append(s.calls, "enable-stack"); return nil }

func stagedRequest(t *testing.T, root string) Request {
	t.Helper()
	stageDir, files := stage(t, map[string]string{
		"etc/nftables.d/gateway.nft": "table inet gateway {}\n",
	})
	return Request{
		Files:    files,
		StageDir: stageDir,
		Options:  Options{Root: root},
	}
}

// The one ordering that matters: a ruleset nft rejects must be refused with the
// live filesystem untouched. If install ran first, a bad config would take the
// LAN offline before anyone could read the error.
func TestValidationFailureWritesNothing(t *testing.T) {
	tools := &fakeTools{failOn: "nft", output: "Error: syntax error"}
	tools.install(t)

	root := t.TempDir()
	req := stagedRequest(t, root)
	sys := &recordingSystem{}
	req.System = sys

	if _, err := Run(req); err == nil {
		t.Fatal("apply accepted a ruleset nft rejected")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/nftables.d/gateway.nft")); err == nil {
		t.Error("the rejected ruleset was installed anyway")
	}
	for _, call := range sys.calls {
		if call != "user:xray" {
			t.Errorf("a service was touched after validation failed: %s", call)
		}
	}
}

// --dry-run must validate and stop. It exists so you can read the diff on a box
// you are not ready to change.
func TestDryRunWritesNothing(t *testing.T) {
	(&fakeTools{}).install(t)
	root := t.TempDir()
	req := stagedRequest(t, root)
	req.DryRun = true
	sys := &recordingSystem{}
	req.System = sys

	plan, err := Run(req)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Changed() {
		t.Error("the plan should still report the pending change")
	}
	if _, err := os.Stat(filepath.Join(root, "etc/nftables.d/gateway.nft")); err == nil {
		t.Error("--dry-run installed a file")
	}
	if len(sys.calls) != 1 || sys.calls[0] != "user:xray" {
		t.Errorf("--dry-run touched services: %v", sys.calls)
	}
}

// The xray account must exist before nft parses a ruleset that names it, or
// validation fails on a fresh box for a reason that has nothing to do with the
// config.
func TestUserIsCreatedBeforeValidation(t *testing.T) {
	tools := &fakeTools{}
	tools.install(t)
	sys := &recordingSystem{}
	req := stagedRequest(t, t.TempDir())
	req.System = sys

	if _, err := Run(req); err != nil {
		t.Fatal(err)
	}
	if len(sys.calls) == 0 || sys.calls[0] != "user:xray" {
		t.Errorf("first system call is %v, want the xray user", sys.calls)
	}
}

func TestSuccessfulApplyOrdersItsSteps(t *testing.T) {
	(&fakeTools{}).install(t)
	root := t.TempDir()
	req := stagedRequest(t, root)
	sys := &recordingSystem{}
	req.System = sys

	var steps []string
	req.Report = func(s Step) { steps = append(steps, s.Name) }

	if _, err := Run(req); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(steps, ","); got != "validate,install,sysctl,systemd,network" {
		t.Errorf("steps ran as %q", got)
	}
	want := "user:xray,sysctl,daemon-reload,enable-stack,restart:gw-network.service"
	if got := strings.Join(sys.calls, ","); got != want {
		t.Errorf("system calls:\n got %q\nwant %q", got, want)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/nftables.d/gateway.nft")); err != nil {
		t.Errorf("the ruleset was not installed: %v", err)
	}
}

// A unit that stopped being rendered is disabled before its file is removed:
// deleting the file first leaves systemd holding an enabled symlink to nothing.
func TestStaleUnitsAreDisabledThenRemoved(t *testing.T) {
	(&fakeTools{}).install(t)
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "etc/systemd/system/gw-update.timer"), "[Timer]\n")

	req := stagedRequest(t, root)
	sys := &recordingSystem{}
	req.System = sys
	if _, err := Run(req); err != nil {
		t.Fatal(err)
	}

	joined := strings.Join(sys.calls, ",")
	if !strings.Contains(joined, "disable:gw-update.timer") {
		t.Errorf("the stale timer was never disabled: %v", sys.calls)
	}
	if _, err := os.Stat(filepath.Join(root, "etc/systemd/system/gw-update.timer")); err == nil {
		t.Error("the stale timer file is still installed")
	}
}

// A system error must surface, not be swallowed into a cheerful exit.
func TestSystemErrorsPropagate(t *testing.T) {
	(&fakeTools{}).install(t)
	req := stagedRequest(t, t.TempDir())
	req.System = &failingSystem{}
	_, err := Run(req)
	if err == nil || !strings.Contains(err.Error(), "sysctl") {
		t.Fatalf("expected the sysctl failure to surface, got %v", err)
	}
}

// failingSystem fails at the sysctl step and inherits the rest.
type failingSystem struct{ recordingSystem }

func (*failingSystem) SysctlReload() error { return errors.New("permission denied") }

var (
	_ System = (*recordingSystem)(nil)
	_ System = (*failingSystem)(nil)
)
