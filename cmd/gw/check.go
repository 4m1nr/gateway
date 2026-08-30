package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/am1nr/gateway/internal/check"
	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/system"
)

func cmdCheck(args []string) error {
	cli.NeedRoot("check")
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	killswitch := fs.Bool("killswitch", false,
		"also prove traffic dies rather than leaking (briefly cuts proxied clients off)")
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	if _, err := parseFlags(fs, args); err != nil {
		return err
	}

	const envPath = "/usr/local/lib/gateway/env"
	if _, err := os.Stat(envPath); err != nil {
		return fmt.Errorf("%s is missing — run 'sudo gw apply' first", envPath)
	}

	runner := &check.Runner{
		Env:        cli.Env(envPath),
		Systemd:    system.Systemd{},
		Killswitch: *killswitch,
	}
	report := runner.Run()

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		printReport(report)
	}

	// A non-zero exit is what makes this usable from a script or a cron job.
	if !report.OK() {
		os.Exit(1)
	}
	return nil
}

func printReport(r check.Report) {
	for _, section := range r.Sections {
		fmt.Printf("\n%s\n", cli.Green(section.Name))
		for _, res := range section.Results {
			switch res.Status {
			case check.Pass:
				fmt.Printf("  %s %s\n", cli.Green("✓"), res.Message)
			case check.Skip:
				fmt.Printf("  %s %s\n", cli.Yellow("–"), res.Message)
			default:
				fmt.Printf("  %s %s\n", cli.Red("✗"), res.Message)
				if res.Detail != "" {
					indent(res.Detail, "     ")
				}
			}
		}
	}
	fmt.Printf("\n%s\n", cli.Green("summary"))
	fmt.Printf("  %d passed, %d failed, %d skipped\n", r.Passed, r.Failed, r.Skipped)
}
