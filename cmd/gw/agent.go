package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/am1nr/gateway/internal/adguard"
	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/geodata"
	"github.com/am1nr/gateway/internal/jsonx"
	"github.com/am1nr/gateway/internal/render"
	"github.com/am1nr/gateway/internal/system"
)

// cmdAgent runs the pieces systemd timers invoke.
//
// Separate from the commands a person types: these are entry points for units,
// and their output goes to the journal rather than a terminal.
func cmdAgent(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: gw agent <geoupdate|adguard-merge>")
	}
	switch args[0] {
	case "geoupdate":
		return cmdGeoUpdate(args[1:])
	case "adguard-merge":
		return cmdAdGuardMerge(args[1:])
	}
	return fmt.Errorf("unknown agent: %s", args[0])
}

func cmdGeoUpdate(args []string) error {
	fs := flag.NewFlagSet("geoupdate", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	check := fs.Bool("check", false, "report what is available, change nothing")
	force := fs.Bool("force", false, "re-download even when nothing upstream changed")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}
	cfg, err := f.load()
	if err != nil {
		return err
	}

	// Bounded overall: this runs from a timer, and a source that never answers
	// must not leave the unit running until the next one fires.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	updater := geodata.Updater{
		MinBytes: int64(cfg.GeoMinBytes),
		Proxy:    bootstrapProxy(cfg.BootstrapProxy),
		Log:      func(format string, a ...any) { cli.Info(format, a...) },
	}

	if *check {
		report := updater.Check(ctx, cfg.GeoSources)
		return emitGeoReport(report, *asJSON, true)
	}

	report, err := updater.Update(ctx, cfg.GeoSources, *force)
	if err != nil {
		return err
	}
	if err := emitGeoReport(report, *asJSON, false); err != nil {
		return err
	}

	// Restarting Xray is what makes new routing data live. Only when something
	// actually changed: a restart drops every live connection on every client,
	// and this runs unattended every day.
	if report.Changed {
		sd := system.Systemd{}
		if sd.Querying().IsActive("xray.service") == "active" {
			cli.Info("restarting Xray to load the new data")
			if err := sd.Restart("xray.service"); err != nil {
				return fmt.Errorf("geodata was installed but Xray would not restart: %w", err)
			}
		}
	}
	if report.Failed > 0 {
		return fmt.Errorf("%d source(s) could not be read", report.Failed)
	}
	return nil
}

func emitGeoReport(report geodata.Report, asJSON, checking bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	for _, r := range report.Results {
		switch {
		case r.Error != "":
			cli.Warn("%s: %s", r.Source, r.Error)
		case checking && r.Changed:
			fmt.Printf("%-28s %s -> %s  (update available)\n", r.Source, orNone2(r.Installed), r.Tag)
		case checking:
			fmt.Printf("%-28s %s  (up to date)\n", r.Source, orNone2(r.Installed))
		case r.Changed:
			cli.Info("%s: updated to %s (%d file(s))", r.Source, r.Tag, len(r.Files))
		default:
			cli.Dim("%s: already at %s", r.Source, orNone2(r.Installed))
		}
		for _, skipped := range r.Skipped {
			cli.Dim("    skipped %s", skipped)
		}
	}
	return nil
}

func orNone2(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// bootstrapProxy applies the shared rule: an explicit override wins, the
// configured proxy is skipped once the tunnel is carrying traffic.
func bootstrapProxy(configured string) string {
	return system.BootstrapProxy(configured, os.Getenv("GW_PROXY"))
}

// cmdAdGuardMerge applies the gateway's AdGuard settings.
//
// Its own entry point because the install script needs it before a full apply
// makes sense — AdGuard has to be configured before the rest of the stack is
// pointed at it.
func cmdAdGuardMerge(args []string) error {
	fs := flag.NewFlagSet("adguard-merge", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	path := fs.String("file", adguardYAML, "path to AdGuardHome.yaml")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}
	cfg, err := f.load()
	if err != nil {
		return err
	}

	raw, err := jsonx.EncodeIndented(render.AdGuardOverrides(cfg))
	if err != nil {
		return err
	}
	var overrides map[string]any
	if err := json.Unmarshal(raw, &overrides); err != nil {
		return err
	}
	if err := adguard.Merge(*path, overrides); err != nil {
		return err
	}
	cli.Info("merged gateway settings into %s (backup: %s.bak)", *path, *path)
	return nil
}
