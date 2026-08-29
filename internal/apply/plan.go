// Package apply installs a rendered tree onto the running system.
//
// The order is deliberate and is the whole safety story: render, diff,
// validate, install, reload. A config that would break the gateway is refused
// before anything is written, because the box being fixed is the box the whole
// house routes through.
package apply

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/am1nr/gateway/internal/diffutil"
	"github.com/am1nr/gateway/internal/render"
)

// Status is what apply would do to one file.
type Status string

const (
	New       Status = "new"
	Changed   Status = "changed"
	Unchanged Status = "unchanged"
)

// Change is one file's difference between the staging tree and the live system.
type Change struct {
	// Path is relative to the tree root, mirroring the target filesystem.
	Path   string `json:"path"`
	Live   string `json:"live"`
	Status Status `json:"status"`
	Mode   string `json:"mode"`
	// Hunks is empty for a new file: there is nothing to diff against, and
	// dumping the whole file as insertions buries the fact that it is new.
	Hunks []diffutil.Hunk `json:"hunks,omitempty"`
	// Binary is set when the live file is not valid UTF-8 text, so the caller
	// reports a replacement rather than a nonsense diff.
	Binary bool `json:"binary,omitempty"`
}

// Plan is everything `gw apply` would change.
type Plan struct {
	Changes []Change `json:"changes"`
	// Stale are units that were installed by a previous apply and are no longer
	// rendered. Leaving one behind means turning a feature off appears to work
	// and changes nothing — the timer stays enabled and keeps firing.
	Stale []string `json:"stale"`
}

// Changed reports whether applying would alter anything.
func (p *Plan) Changed() bool {
	if len(p.Stale) > 0 {
		return true
	}
	for _, c := range p.Changes {
		if c.Status != Unchanged {
			return true
		}
	}
	return false
}

// Pending returns only the entries apply would act on.
func (p *Plan) Pending() []Change {
	var out []Change
	for _, c := range p.Changes {
		if c.Status != Unchanged {
			out = append(out, c)
		}
	}
	return out
}

// staleUnits are units apply removes when they stop being rendered. Only units
// whose absence is itself a setting belong here: a unit that vanished because
// the template was deleted is a code change, not a config change.
var staleUnits = []string{
	"etc/systemd/system/gw-update.timer",
	"etc/systemd/system/gw-update.service",
	"etc/systemd/system/gw-web.service",
	"etc/systemd/system/gw-tailscale-exception.service",
}

// Options control where the plan is applied.
type Options struct {
	// Root is the filesystem the tree is compared against and installed into.
	// "/" in production; a temp dir in tests.
	Root string
	// Context is how many unchanged lines surround each diff hunk.
	Context int
}

func (o Options) root() string {
	if o.Root == "" {
		return "/"
	}
	return o.Root
}

func (o Options) context() int {
	if o.Context <= 0 {
		return 3
	}
	return o.Context
}

// Compare diffs a rendered tree against the live filesystem. It reads only, so
// it is safe to call at any time — `gw diff` is exactly this.
func Compare(files []render.File, opt Options) (*Plan, error) {
	plan := &Plan{}
	rendered := map[string]bool{}

	for _, f := range files {
		if !f.Installed() {
			continue
		}
		rendered[f.Path] = true
		live := filepath.Join(opt.root(), f.Path)
		change := Change{
			Path: f.Path,
			Live: "/" + f.Path,
			Mode: fmt.Sprintf("%04o", f.Mode.Perm()),
		}

		current, err := os.ReadFile(live)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			change.Status = New
		case err != nil:
			return nil, fmt.Errorf("reading %s: %w", live, err)
		case string(current) == f.Content:
			change.Status = Unchanged
		default:
			change.Status = Changed
			if isText(current) {
				change.Hunks = diffutil.Unified(string(current), f.Content, opt.context())
			} else {
				change.Binary = true
			}
		}
		plan.Changes = append(plan.Changes, change)
	}

	for _, unit := range staleUnits {
		if rendered[unit] {
			continue
		}
		if _, err := os.Stat(filepath.Join(opt.root(), unit)); err == nil {
			plan.Stale = append(plan.Stale, unit)
		}
	}
	return plan, nil
}

// isText reports whether content can be diffed line by line. Everything the
// gateway renders is text; this guards against a live file that is not.
func isText(data []byte) bool {
	for _, b := range data {
		if b == 0 {
			return false
		}
	}
	return true
}
