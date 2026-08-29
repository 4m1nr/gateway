package apply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/render"
)

// fakeTools replaces the external commands for one test.
type fakeTools struct {
	calls  []string
	failOn string
	output string
}

func (f *fakeTools) install(t *testing.T) {
	t.Helper()
	oldRunner, oldLook := runner, lookPath
	t.Cleanup(func() { runner, lookPath = oldRunner, oldLook })

	lookPath = func(name string) (string, error) { return "/usr/bin/" + name, nil }
	runner = func(_ context.Context, name string, args ...string) (string, error) {
		f.calls = append(f.calls, name+" "+strings.Join(args, " "))
		if f.failOn != "" && strings.Contains(name, f.failOn) {
			return f.output, errors.New("exit status 1")
		}
		return "", nil
	}
}

func stage(t *testing.T, files map[string]string) (string, []render.File) {
	t.Helper()
	dir := t.TempDir()
	var out []render.File
	for path, content := range files {
		full := filepath.Join(dir, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		out = append(out, render.File{Path: path, Content: content, Mode: 0o644})
	}
	return dir, out
}

func TestValidateRunsEveryCheck(t *testing.T) {
	tools := &fakeTools{}
	tools.install(t)

	dir, files := stage(t, map[string]string{
		"etc/nftables.d/gateway.nft":         "table inet gateway {}\n",
		"etc/sudoers.d/gw-web":               "gwweb ALL=(root) NOPASSWD: /x\n",
		"etc/systemd/system/gw-update.timer": "[Timer]\nOnCalendar=weekly\n",
	})
	if err := Validate(dir, files, Options{}); err != nil {
		t.Fatalf("validate: %v", err)
	}

	joined := strings.Join(tools.calls, "\n")
	for _, want := range []string{"nft -c -f", "visudo -cf", "systemd-analyze calendar weekly"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected a %q call, got:\n%s", want, joined)
		}
	}
}

// A ruleset nft rejects must never reach /etc. This is the check that stops a
// bad config becoming a box with no firewall.
func TestValidateRejectsBadRuleset(t *testing.T) {
	tools := &fakeTools{failOn: "nft", output: "gateway.nft:12:3-8: Error: syntax error"}
	tools.install(t)

	dir, files := stage(t, map[string]string{"etc/nftables.d/gateway.nft": "nonsense\n"})
	err := Validate(dir, files, Options{})
	if err == nil {
		t.Fatal("a ruleset nft rejected was accepted")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is %T, want *ValidationError", err)
	}
	if !strings.Contains(err.Error(), "syntax error") {
		t.Errorf("the error hides what nft actually said: %v", err)
	}
}

// An OnCalendar systemd cannot parse produces a timer that loads and never
// fires, so the setting reads as if it worked.
func TestValidateRejectsBadSchedule(t *testing.T) {
	tools := &fakeTools{failOn: "systemd-analyze"}
	tools.install(t)

	dir, files := stage(t, map[string]string{
		"etc/systemd/system/gw-update.timer": "[Timer]\nOnCalendar=every other tuesday\n",
	})
	err := Validate(dir, files, Options{})
	if err == nil {
		t.Fatal("an unparseable OnCalendar was accepted")
	}
	if !strings.Contains(err.Error(), "every other tuesday") {
		t.Errorf("the error does not quote the offending schedule: %v", err)
	}
}

// A sudoers syntax error can make sudo refuse to run at all, which locks you
// out of fixing it.
func TestValidateRejectsBadSudoers(t *testing.T) {
	tools := &fakeTools{failOn: "visudo"}
	tools.install(t)

	dir, files := stage(t, map[string]string{"etc/sudoers.d/gw-web": "garbage\n"})
	if err := Validate(dir, files, Options{}); err == nil {
		t.Fatal("an invalid sudoers fragment was accepted")
	}
}

// `gw render` and the offline suite run where Xray and nft were never
// installed. Refusing there would make the common case unusable to guard
// against one that cannot happen — apply never reloads what it could not check.
func TestValidateSkipsMissingTools(t *testing.T) {
	oldRunner, oldLook := runner, lookPath
	t.Cleanup(func() { runner, lookPath = oldRunner, oldLook })
	lookPath = func(string) (string, error) { return "", errors.New("not found") }
	runner = func(context.Context, string, ...string) (string, error) {
		t.Error("a command was run even though the tool is not installed")
		return "", nil
	}

	dir, files := stage(t, map[string]string{
		"etc/nftables.d/gateway.nft":         "table inet gateway {}\n",
		"etc/sudoers.d/gw-web":               "x\n",
		"etc/systemd/system/gw-update.timer": "[Timer]\nOnCalendar=weekly\n",
	})
	if err := Validate(dir, files, Options{}); err != nil {
		t.Fatalf("validation should be skipped, not failed: %v", err)
	}
}

// Nothing is checked that was not rendered — auto_update = "off" removes the
// timer, and validating a file that is not there would fail on an empty read.
func TestValidateSkipsUnrenderedFiles(t *testing.T) {
	tools := &fakeTools{}
	tools.install(t)
	dir, files := stage(t, map[string]string{"etc/nftables.d/gateway.nft": "table inet gateway {}\n"})
	if err := Validate(dir, files, Options{}); err != nil {
		t.Fatal(err)
	}
	for _, call := range tools.calls {
		if strings.Contains(call, "systemd-analyze") || strings.Contains(call, "visudo") {
			t.Errorf("checked a file that was never rendered: %s", call)
		}
	}
}
