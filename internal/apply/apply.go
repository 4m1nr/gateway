package apply

import (
	"fmt"
	"sort"
	"strings"

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
	// ReconfigureLinks makes networkd re-read the .network files and apply them
	// to the named links. Disruptive: it briefly drops each link, so it is
	// called only when one of those files actually changed.
	ReconfigureLinks(links map[string]string) error
	// PruneLinkAddresses removes any address a link carries that the config no
	// longer names, and returns what it removed. links maps an interface name
	// to the address it should carry ("10.0.0.2/24"); an empty value means the
	// address comes from a lease, and nothing on that link is touched.
	//
	// Not disruptive — it only deletes what should not be there — so it runs on
	// every apply rather than only when the config changed. An address left
	// behind by an earlier renumbering is not something the box grows out of.
	PruneLinkAddresses(links map[string]string) ([]string, error)
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
	// Links are the interfaces the rendered .network files describe, mapped to
	// the address each should carry — empty for a link addressed by DHCP. They
	// are reconfigured only when one of those files actually changed.
	Links map[string]string

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
				// Only things under etc/systemd/system/ are units systemd can
				// be asked about. A .network file is configuration, not a unit,
				// and disabling it is a meaningless command.
				if strings.HasPrefix(unit, "etc/systemd/system/") {
					_ = req.System.Disable(unitName(unit))
				}
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

	// Renumbering, in two halves that are deliberately gated differently.
	//
	// networkd is not told to re-read anything by installing a file, so before
	// this the new address only appeared at the next reboot — and then appeared
	// BESIDE the old one, because networkd does not withdraw an address just
	// because the configuration that set it is gone. The card ends up carrying
	// both, the old one still answering, and nothing in `gw apply` says which
	// is meant to be there.
	//
	// Making networkd re-read is disruptive, so it happens only when one of
	// those files actually changed. Removing an address the config no longer
	// names is not, so it happens every time: a box that already carries a
	// leftover from an earlier renumbering never changes its .network file
	// again, and would otherwise keep that address forever.
	if len(req.Links) > 0 {
		if networkChanged(plan) {
			req.Report.report("links", "reconfiguring "+joinLinks(req.Links))
			if err := req.System.ReconfigureLinks(req.Links); err != nil {
				// Not fatal, and deliberately so: this runs AFTER the tree is
				// installed, so returning here would leave the files written
				// and the firewall never reloaded — strictly worse than a card
				// that keeps its old address until someone looks. Said plainly
				// instead, because a silent half-renumbering is the thing this
				// step exists to prevent.
				req.Report.report("links", "could not reconfigure the links: "+err.Error()+
					" — check `ip -br addr`; the card may still be on its old address")
			}
		}
		removed, err := req.System.PruneLinkAddresses(req.Links)
		for _, addr := range removed {
			req.Report.report("links", "removed the stale address "+addr)
		}
		if err != nil {
			req.Report.report("links", "could not check the link addresses: "+err.Error()+
				" — compare `ip -br addr` against [net] by hand")
		}
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

// networkChanged reports whether this apply touched a networkd unit.
//
// Reconfiguring on every apply would be wrong: it briefly drops the link, and
// almost every apply is a routing or client change that has nothing to do with
// addressing.
func networkChanged(plan *Plan) bool {
	for _, c := range plan.Pending() {
		if strings.HasPrefix(c.Path, "etc/systemd/network/") {
			return true
		}
	}
	// A unit that stopped being rendered counts too: going from two cards back
	// to one deletes the LAN unit, and without a reconfigure that card keeps
	// the address the config no longer gives it.
	for _, unit := range plan.Stale {
		if strings.HasPrefix(unit, "etc/systemd/network/") {
			return true
		}
	}
	return false
}

// joinLinks names the links in a stable order, for the progress line.
func joinLinks(links map[string]string) string {
	names := make([]string, 0, len(links))
	for name := range links {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
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
