package apply

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// recordingSystem logs every system call in order.
type recordingSystem struct {
	calls []string
	// removed is what ReconfigureLinks reports having pruned.
	removed []string
}

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
func (s *recordingSystem) ReconfigureLinks(links map[string]string) ([]string, error) {
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	s.calls = append(s.calls, "reconfigure:"+strings.Join(names, ","))
	return s.removed, nil
}

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

// Renumbering must reconfigure the link, and only when a .network file actually
// changed: reconfiguring drops the link for a moment, and almost every apply is
// a routing change that has nothing to do with addressing.
func TestNetworkChangeReconfiguresLinks(t *testing.T) {
	root := t.TempDir()
	// No ruleset here: nft -c needs privileges this test does not have, and the
	// thing under test is the link, not the firewall.
	stageDir, files := stage(t, map[string]string{
		"etc/systemd/network/10-gateway-wan.network": "[Network]\nAddress=10.0.0.2/24\n",
	})
	sys := &recordingSystem{removed: []string{"eth0 192.168.1.2/24"}}
	var steps []string
	req := Request{
		Files:    files,
		StageDir: stageDir,
		Links:    map[string]string{"eth0": "10.0.0.2/24"},
		Options:  Options{Root: root},
		System:   sys,
		Report:   func(s Step) { steps = append(steps, s.Name+": "+s.Detail) },
	}
	if _, err := Run(req); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !containsCall(sys.calls, "reconfigure:eth0") {
		t.Fatalf("the .network file changed but the link was not reconfigured: %v", sys.calls)
	}
	if !containsStep(steps, "removed the stale address eth0 192.168.1.2/24") {
		t.Fatalf("the pruned address was not reported: %v", steps)
	}

	// Second apply: nothing changed, so the link must be left alone.
	sys2 := &recordingSystem{}
	req.System = sys2
	if _, err := Run(req); err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if containsCall(sys2.calls, "reconfigure:eth0") {
		t.Fatalf("nothing changed but the link was reconfigured anyway: %v", sys2.calls)
	}
}

func containsCall(calls []string, want string) bool {
	for _, c := range calls {
		if c == want {
			return true
		}
	}
	return false
}

func containsStep(steps []string, want string) bool {
	for _, s := range steps {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// Going back to one card removes the LAN unit — and must reconfigure the link
// as well, or that card keeps the address the config no longer gives it.
func TestRevertingToOneCardReconfiguresLinks(t *testing.T) {
	root := t.TempDir()
	lan := filepath.Join(root, "etc/systemd/network/15-gateway-lan.network")
	if err := os.MkdirAll(filepath.Dir(lan), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lan, []byte("[Network]\nAddress=192.168.10.1/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Rendered without it: this config has one card again.
	stageDir, files := stage(t, map[string]string{
		"etc/systemd/network/10-gateway-wan.network": "[Network]\nAddress=10.0.0.2/24\n",
	})
	sys := &recordingSystem{}
	if _, err := Run(Request{
		Files:    files,
		StageDir: stageDir,
		Links:    map[string]string{"eth0": "10.0.0.2/24"},
		Options:  Options{Root: root},
		System:   sys,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if _, err := os.Stat(lan); !os.IsNotExist(err) {
		t.Fatalf("the LAN unit survived: networkd keeps addressing a side the config dropped")
	}
	if !containsCall(sys.calls, "reconfigure:eth0") {
		t.Fatalf("the LAN unit was removed but no link was reconfigured: %v", sys.calls)
	}
	// A .network file is configuration, not a unit, so nothing should try to
	// disable it.
	for _, c := range sys.calls {
		if strings.HasPrefix(c, "disable:") && strings.Contains(c, ".network") {
			t.Fatalf("tried to disable a .network file as if it were a unit: %s", c)
		}
	}
}
