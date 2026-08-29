package apply

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/render"
)

// runner executes an external command. Replaced in tests; nothing else assigns
// to it.
var runner = func(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// lookPath is exec.LookPath, replaced in tests.
var lookPath = exec.LookPath

// ValidationError names the check that failed and what the tool said.
type ValidationError struct {
	Check  string
	Output string
	Err    error
}

func (e *ValidationError) Error() string {
	out := strings.TrimSpace(e.Output)
	if out == "" {
		return fmt.Sprintf("%s: %v", e.Check, e.Err)
	}
	return fmt.Sprintf("%s:\n%s", e.Check, out)
}

func (e *ValidationError) Unwrap() error { return e.Err }

// onCalendarRE pulls the schedule out of the staged timer unit.
var onCalendarRE = regexp.MustCompile(`(?m)^OnCalendar=(.*)$`)

// Validate checks the staged tree with the real tools, before anything is
// installed.
//
// This is the difference between a config error and a drive back to the house.
// Every check runs against the staging directory, so a ruleset nft rejects or a
// config Xray rejects never reaches /etc at all — the alternative is a
// half-applied gateway that comes up with no firewall.
//
// Checks whose tool is absent are skipped rather than failed: `gw render` and
// the test suite run on machines where Xray was never installed, and refusing
// there would make the common case unusable to protect against a case that
// cannot happen (apply reloads nothing it could not validate).
func Validate(stageDir string, files []render.File, opt Options) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	rendered := map[string]bool{}
	for _, f := range files {
		rendered[f.Path] = true
	}

	// The nftables ruleset. A syntax or semantic error here means gw-network
	// fails to load and the box forwards with no firewall at all.
	if rendered["etc/nftables.d/gateway.nft"] {
		if nft, err := lookPath("nft"); err == nil {
			path := filepath.Join(stageDir, "etc/nftables.d/gateway.nft")
			if out, err := runner(ctx, nft, "-c", "-f", path); err != nil {
				return &ValidationError{Check: "nftables ruleset rejected", Output: out, Err: err}
			}
		}
	}

	// The Xray config. Checked with the installed binary, which is the same one
	// that will be asked to run it.
	if rendered["usr/local/etc/xray/config.json"] {
		if _, err := os.Stat("/usr/local/bin/xray"); err == nil {
			path := filepath.Join(stageDir, "usr/local/etc/xray/config.json")
			if out, err := runner(ctx, "/usr/local/bin/xray", "run", "-test", "-config", path); err != nil {
				return &ValidationError{Check: "Xray rejected its config", Output: out, Err: err}
			}
		}
	}

	// The sudoers fragment. A syntax error in /etc/sudoers.d can make sudo
	// refuse to run at all, which locks you out of fixing it.
	if rendered["etc/sudoers.d/gw-web"] {
		if visudo, err := lookPath("visudo"); err == nil {
			path := filepath.Join(stageDir, "etc/sudoers.d/gw-web")
			if out, err := runner(ctx, visudo, "-cf", path); err != nil {
				return &ValidationError{
					Check:  "generated sudoers file is invalid — refusing to install it",
					Output: out, Err: err,
				}
			}
		}
	}

	// The update schedule. An OnCalendar systemd cannot parse does not fail
	// loudly: the timer unit loads, never fires, and the setting reads as if it
	// worked.
	if rendered["etc/systemd/system/gw-update.timer"] {
		if analyze, err := lookPath("systemd-analyze"); err == nil {
			raw, err := os.ReadFile(filepath.Join(stageDir, "etc/systemd/system/gw-update.timer"))
			if err != nil {
				return fmt.Errorf("reading the staged update timer: %w", err)
			}
			m := onCalendarRE.FindSubmatch(raw)
			if m == nil {
				return &ValidationError{
					Check: "the update timer has no OnCalendar= line",
					Err:   fmt.Errorf("missing OnCalendar"),
				}
			}
			cal := strings.TrimSpace(string(m[1]))
			if out, err := runner(ctx, analyze, "calendar", cal); err != nil {
				return &ValidationError{
					Check: fmt.Sprintf("system.auto_update_schedule = %q is not a valid "+
						"systemd OnCalendar expression. Try: weekly, daily, or \"Sun 04:00\"", cal),
					Output: out, Err: err,
				}
			}
		}
	}
	return nil
}
