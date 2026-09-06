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
	"sort"
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

// ReconfigureLinks makes systemd-networkd adopt the freshly installed .network
// files.
//
// Installing one tells networkd nothing on its own: the change appears at the
// next reboot and not before. This is the half that is disruptive — each link
// goes down for a moment as it is reconfigured — which is why apply calls it
// only when one of those files actually changed.
//
// reload before reconfigure, and neither is a restart: restarting networkd
// takes every link down at once, on a box whose LAN is served through it.
func (s Systemd) ReconfigureLinks(links map[string]string) error {
	names, ok := managedLinks(links)
	if !ok {
		return nil
	}
	if _, err := s.run("networkctl", "reload"); err != nil {
		return err
	}
	for _, name := range names {
		if _, err := s.run("networkctl", "reconfigure", name); err != nil {
			return err
		}
	}
	return nil
}

// PruneLinkAddresses leaves each link carrying only the address the config
// names, and returns the ones it removed.
//
// This is the surprising half. When networkd re-reads a .network file it adds
// the new address and KEEPS the old one — it does not withdraw an address
// merely because the configuration that set it is gone. Renumbering a box
// therefore left the card holding both, the old one still answering, with
// nothing anywhere saying which was meant to be there.
//
// Deleting an address that should not be on the link does not disturb one that
// should, so unlike ReconfigureLinks this runs on every apply. A box that is
// already carrying a leftover never changes its .network file again, and
// gating this on such a change would mean it kept that address forever.
//
// links maps an interface to the address it should carry, as "10.0.0.2/24". An
// empty value means the address comes from a lease; that link is left entirely
// alone, because there is no configured address to judge it against.
func (s Systemd) PruneLinkAddresses(links map[string]string) ([]string, error) {
	names, ok := managedLinks(links)
	if !ok {
		return nil, nil
	}
	var removed []string
	for _, name := range names {
		want := links[name]
		if want == "" {
			continue
		}
		stale, err := s.pruneAddresses(name, want)
		removed = append(removed, stale...)
		if err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// managedLinks returns the interface names in a stable order, and false when
// there is nothing to act on.
//
// A box that does not use networkd is the "nothing to act on" case, and it is
// not a failure: `gw apply` runs on boxes partway through bootstrap, before the
// switch to networkd has happened. Nothing is pruned there either — without
// networkd, this code has no claim to know what belongs on the link.
func managedLinks(links map[string]string) ([]string, bool) {
	if len(links) == 0 {
		return nil, false
	}
	if _, err := exec.LookPath("networkctl"); err != nil {
		return nil, false
	}
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, true
}

// pruneAddresses removes every permanent global IPv4 address on a link except
// the one the config names.
//
// Scoped tightly on purpose. Only IPv4, only global scope — link-local and the
// loopback range are the kernel's business. And never a "dynamic" address: that
// came from a lease rather than from this config, so there is no configured
// value it can be judged against, and deleting it would cut the uplink on a box
// running wan_dhcp.
func (s Systemd) pruneAddresses(iface, want string) ([]string, error) {
	out, err := s.run("ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global")
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" || strings.Contains(line, " dynamic ") {
			continue
		}
		addr := inetAddr(line)
		if addr == "" || addr == want {
			continue
		}
		if _, err := s.run("ip", "addr", "del", addr, "dev", iface); err != nil {
			return removed, err
		}
		removed = append(removed, iface+" "+addr)
	}
	return removed, nil
}

// inetAddr pulls the CIDR out of one `ip -o addr` line, or "" if there is none.
func inetAddr(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if f == "inet" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
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

// Mask makes a unit unstartable. Used for nftables.service, which would
// otherwise flush the ruleset out from under gw-network.
func (s Systemd) Mask(unit string) error {
	_, err := s.run("systemctl", "mask", unit)
	return err
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
