package apply

import (
	"fmt"

	"github.com/am1nr/gateway/internal/render"
)

// Step is one stage of an apply, reported as it happens so the CLI can narrate
// and the dashboard can stream progress.
type Step struct {
	Name   string
	Detail string
}

// Reporter receives progress. nil is fine; Run checks.
type Reporter func(Step)

func (r Reporter) report(name, detail string) {
	if r != nil {
		r(Step{Name: name, Detail: detail})
	}
}

// System is the part of apply that touches services. It is an interface so the
// ordering of the whole sequence can be tested without root, systemd, or a
// gateway.
type System interface {
	// EnsureUser creates a system account if it is missing. The nftables
	// ruleset references the xray user by name and nft resolves it at load
	// time, so the account has to exist before the firewall is loaded.
	EnsureUser(name string) error
	// SysctlReload applies /etc/sysctl.d.
	SysctlReload() error
	// DaemonReload makes systemd re-read unit files.
	DaemonReload() error
	// Restart restarts a unit.
	Restart(unit string) error
	// Disable stops a unit and removes it from boot.
	Disable(unit string) error
	// EnableStack enables everything that is installed, for boot.
	EnableStack() error
}

// Request is one invocation of apply.
type Request struct {
	// Files is the rendered tree.
	Files []render.File
	// StageDir is where Files were written, for the validators.
	StageDir string
	// DryRun stops after validation, having written nothing.
	DryRun bool

	Options Options
	System  System
	Report  Reporter
}

// Run renders, diffs, validates, installs and reloads — in that order.
//
// The ordering is the entire safety story. Validation happens against the
// staging tree while the live system is untouched, so a ruleset nft rejects or
// a config Xray rejects is refused rather than half-applied. Nothing below the
// validation step runs if it fails.
func Run(req Request) (*Plan, error) {
	plan, err := Compare(req.Files, req.Options)
	if err != nil {
		return nil, err
	}

	// Before validation, because the ruleset names the xray user and nft
	// resolves it to a uid while parsing — `nft -c` fails on a box where the
	// account does not exist yet.
	if req.System != nil {
		if err := req.System.EnsureUser("xray"); err != nil {
			return plan, fmt.Errorf("creating the xray system user: %w", err)
		}
	}

	req.Report.report("validate", "checking the staged tree with nft, xray and visudo")
	if err := Validate(req.StageDir, req.Files, req.Options); err != nil {
		return plan, err
	}

	if req.DryRun {
		req.Report.report("dry-run", "nothing written")
		return plan, nil
	}

	req.Report.report("install", fmt.Sprintf("%d files", len(plan.Pending())))
	if _, err := Install(req.Files, req.Options); err != nil {
		return plan, err
	}

	if len(plan.Stale) > 0 {
		req.Report.report("remove", fmt.Sprintf("%d units no longer in the config", len(plan.Stale)))
		if req.System != nil {
			for _, unit := range plan.Stale {
				_ = req.System.Disable(unitName(unit))
			}
		}
		if err := RemoveStale(plan, req.Options); err != nil {
			return plan, err
		}
	}

	if req.System == nil {
		return plan, nil
	}

	req.Report.report("sysctl", "applying kernel settings")
	if err := req.System.SysctlReload(); err != nil {
		return plan, fmt.Errorf("applying sysctl: %w", err)
	}

	req.Report.report("systemd", "reloading unit files")
	if err := req.System.DaemonReload(); err != nil {
		return plan, fmt.Errorf("systemd daemon-reload: %w", err)
	}
	if err := req.System.EnableStack(); err != nil {
		return plan, fmt.Errorf("enabling the gateway stack: %w", err)
	}

	// Policy routing and the firewall first: Xray's listener is useless if
	// nothing is being diverted to it, and restarting in the other order leaves
	// a window where clients are intercepted with no one listening.
	req.Report.report("network", "reloading policy routing and the firewall")
	if err := req.System.Restart("gw-network.service"); err != nil {
		return plan, fmt.Errorf("restarting gw-network: %w", err)
	}
	return plan, nil
}

// unitName turns a staged path back into a systemd unit name.
func unitName(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			return path[i+1:]
		}
	}
	return path
}
