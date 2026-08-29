package action

import (
	"path/filepath"

	"github.com/am1nr/gateway/internal/apply"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/render"
	"github.com/am1nr/gateway/internal/system"
)

// stage renders the config into the staging tree and returns both.
func (h Handler) stage() (*config.Config, []render.File, string, error) {
	cfg, err := config.Load(h.Config)
	if err != nil {
		return nil, nil, "", err
	}
	stageDir := filepath.Join(h.Repo, "build")
	files, err := render.Write(cfg, stageDir, render.Options{Repo: h.Repo})
	if err != nil {
		return nil, nil, "", err
	}
	return cfg, files, stageDir, nil
}

// diff reports what apply would change, without changing anything.
func (h Handler) diff() Response {
	_, files, _, err := h.stage()
	if err != nil {
		return fail("%v", err)
	}
	plan, err := apply.Compare(files, apply.Options{Root: h.rootOrSlash()})
	if err != nil {
		return fail("%v", err)
	}
	return ok(map[string]any{
		"changes": plan.Pending(),
		"stale":   plan.Stale,
		"changed": plan.Changed(),
	})
}

// applyNow renders, validates and installs.
//
// Validation happens against the staging tree while the live system is
// untouched, so a ruleset nft rejects or a config Xray rejects is refused
// rather than half-applied. The dashboard is the most likely place for someone
// to make a change they have not thought through, which is exactly why this
// path is the same one `gw apply` uses rather than a shortcut.
func (h Handler) applyNow() Response {
	_, files, stageDir, err := h.stage()
	if err != nil {
		return fail("%v", err)
	}

	var steps []string
	plan, err := apply.Run(apply.Request{
		Files:    files,
		StageDir: stageDir,
		Options:  apply.Options{Root: h.rootOrSlash()},
		System:   h.applySystem(),
		Report: func(s apply.Step) {
			steps = append(steps, s.Name+": "+s.Detail)
		},
	})
	if err != nil {
		// Shown verbatim in the dashboard: it carries nft's or Xray's own
		// words, which say what is actually wrong.
		return fail("%v", err)
	}

	// Restarting Xray is what makes a new config live, and it is deliberately
	// last: it drops every live connection on every client, so nothing else
	// should be able to fail after it.
	if sd := h.Systemd; sd.Exists("xray.service") {
		if err := sd.Restart("xray.service"); err != nil {
			return fail("the config was installed but Xray would not restart: %v", err)
		}
		steps = append(steps, "xray: restarted")
	}

	return Response{
		OK:      true,
		Message: "applied",
		Data: map[string]any{
			"steps":   steps,
			"changed": len(plan.Pending()),
		},
	}
}

func (h Handler) rootOrSlash() string {
	if h.Root == "" {
		return "/"
	}
	return h.Root
}

// applySystem returns the system interface, or nil when operating on a
// throwaway root — restarting the real gateway's units from a --root run would
// be a surprising thing for it to do.
func (h Handler) applySystem() apply.System {
	if h.rootOrSlash() != "/" {
		return nil
	}
	return system.Systemd{}
}
