// Package system wraps the handful of privileged operations the gateway
// performs: systemd units, sysctl, and creating service accounts.
//
// Every call uses an argument slice, never a shell. Nothing that reaches here
// is ever interpolated into a command line.
package system

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"
)

// Systemd talks to the running init system.
type Systemd struct {
	// Timeout bounds each command. Zero means 2 minutes, which is long enough
	// for a unit that is slow to stop and short enough not to hang apply.
	Timeout time.Duration
}

func (s Systemd) timeout() time.Duration {
	if s.Timeout == 0 {
		return 2 * time.Minute
	}
	return s.Timeout
}

// Querying is a Systemd whose calls are bounded tightly, for read-only status
// where a hung systemctl must not stall the caller. Restarting a unit can
// legitimately take a minute; asking what state it is in cannot.
func (s Systemd) Querying() Systemd {
	if s.Timeout != 0 {
		return s
	}
	return Systemd{Timeout: 10 * time.Second}
}

func (s Systemd) run(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout())
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, msg)
	}
	return string(out), nil
}

// EnsureUser creates a locked-down system account if it does not exist.
//
// The nftables ruleset names the xray user and nft resolves it to a uid while
// parsing, so the account has to exist before the firewall can even be
// validated.
func (s Systemd) EnsureUser(name string) error {
	if _, err := user.Lookup(name); err == nil {
		return nil
	}
	// No home, no shell, no group memberships: it exists to own one process.
	_, err := s.run("useradd", "--system", "--no-create-home",
		"--shell", "/usr/sbin/nologin", name)
	return err
}

// SysctlReload applies everything in /etc/sysctl.d.
func (s Systemd) SysctlReload() error {
	_, err := s.run("sysctl", "--system")
	return err
}

// DaemonReload makes systemd re-read unit files.
func (s Systemd) DaemonReload() error {
	_, err := s.run("systemctl", "daemon-reload")
	return err
}

// Restart restarts a unit. Restart rather than `enable --now`: the unit is
// usually already running and would otherwise keep serving the previous config.
func (s Systemd) Restart(unit string) error {
	_, err := s.run("systemctl", "restart", unit)
	return err
}

// Start starts a unit.
func (s Systemd) Start(unit string) error {
	_, err := s.run("systemctl", "start", unit)
	return err
}

// Stop stops a unit.
func (s Systemd) Stop(unit string) error {
	_, err := s.run("systemctl", "stop", unit)
	return err
}

// Disable stops a unit and removes it from boot. A unit that is already gone is
// not an error — this runs during cleanup.
func (s Systemd) Disable(unit string) error {
	_, _ = s.run("systemctl", "disable", "--now", unit)
	return nil
}

// Enable adds units to boot. Enabling a unit that does not exist fails the
// whole call, so callers pass only what is installed.
func (s Systemd) Enable(units ...string) error {
	if len(units) == 0 {
		return nil
	}
	_, err := s.run("systemctl", append([]string{"enable"}, units...)...)
	return err
}

// Exists reports whether systemd knows about a unit.
func (s Systemd) Exists(unit string) bool {
	_, err := s.run("systemctl", "cat", unit)
	return err == nil
}

// IsActive reports a unit's ActiveState, or "missing".
func (s Systemd) IsActive(unit string) string {
	out, err := s.run("systemctl", "is-active", unit)
	if state := strings.TrimSpace(out); state != "" {
		return state
	}
	if err != nil {
		return "missing"
	}
	return "unknown"
}

// IsEnabled reports whether a unit starts at boot.
func (s Systemd) IsEnabled(unit string) string {
	out, _ := s.run("systemctl", "is-enabled", unit)
	if state := strings.TrimSpace(out); state != "" {
		return state
	}
	return "disabled"
}

// Show reads one unit's properties.
func (s Systemd) Show(unit string, properties ...string) map[string]string {
	all := s.ShowMany([]string{unit}, properties...)
	return all[unit]
}

// ShowMany reads properties for several units in a single call.
//
// One systemctl invocation per unit costs about a second each on a thin
// client, and the dashboard polls status continuously — nine units was nine
// seconds. systemd separates each unit's block with a blank line and identifies
// it with Id=, so one call answers for all of them.
func (s Systemd) ShowMany(units []string, properties ...string) map[string]map[string]string {
	out := map[string]map[string]string{}
	if len(units) == 0 {
		return out
	}
	// Id is always requested: it is how each block is attributed to its unit,
	// and systemd may report a different name than the one asked for (an alias,
	// or a template instance).
	args := append([]string{"show"}, units...)
	args = append(args, "--property=Id")
	for _, p := range properties {
		args = append(args, "--property="+p)
	}
	raw, _ := s.run("systemctl", args...)

	blocks := strings.Split(raw, "\n\n")
	for i, block := range blocks {
		props := map[string]string{}
		for _, line := range strings.Split(block, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
				props[k] = v
			}
		}
		if len(props) == 0 {
			continue
		}
		name := props["Id"]
		if name == "" && i < len(units) {
			// A unit systemd knows nothing about still gets a block, but
			// without an Id. Positional order is systemd's own, so fall back to
			// it rather than dropping the entry.
			name = units[i]
		}
		if name != "" {
			out[name] = props
		}
	}
	return out
}

// StackUnits is the gateway stack. gateway.target is the umbrella; the rest are
// its members. tailscaled is deliberately absent — it is Wanted by the target
// but not PartOf it, so restarting the stack cannot drop the session you are
// managing it over.
var StackUnits = []string{
	"gateway.target",
	"gw-network.service",
	"xray.service",
	"gw-web.service",
	"gw-health.timer",
	"gw-geoupdate.timer",
	"gw-update.timer",
}

// EnableStack enables everything that is actually installed.
//
// Enabling gateway.target alone is not enough: [Install] symlinks are created
// by enabling each member, and the target's Wants= only pulls in units that
// exist. Enabling both is what makes a cold boot come up complete.
func (s Systemd) EnableStack() error {
	var installed []string
	for _, unit := range StackUnits {
		if _, err := os.Stat("/etc/systemd/system/" + unit); err == nil {
			installed = append(installed, unit)
		}
	}
	if len(installed) == 0 {
		return nil
	}
	if err := s.Enable(installed...); err != nil {
		return err
	}
	// Third-party units the stack depends on. AdGuard installs its own unit and
	// ours is a drop-in on top of it; chrony-wait is what gives xray.service's
	// After=time-sync.target any meaning, because a thin client with a flat
	// CMOS battery boots years out of date and TLS fails on skew.
	for _, unit := range []string{"AdGuardHome.service", "tailscaled.service", "chrony-wait.service"} {
		if s.Exists(unit) {
			_ = s.Enable(unit)
		}
	}
	return nil
}
