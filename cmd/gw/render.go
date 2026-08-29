package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/am1nr/gateway/internal/apply"
	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/diffutil"
	"github.com/am1nr/gateway/internal/render"
)

// common flags shared by render, diff and apply.
type commonFlags struct {
	config string
	out    string
	root   string
	paths  cli.Paths
}

func (c *commonFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&c.config, "config", "", "path to gateway.toml")
	fs.StringVar(&c.out, "out", "", "staging tree to write")
	// Root exists so the whole install path can be exercised against a
	// throwaway directory instead of the live filesystem.
	fs.StringVar(&c.root, "root", "/", "filesystem to compare against and install into")
}

func (c *commonFlags) resolve() error {
	paths, err := cli.Resolve()
	if err != nil {
		return err
	}
	if c.config != "" {
		paths.Config = c.config
	}
	if c.out != "" {
		paths.Build = c.out
	}
	c.paths = paths
	return nil
}

// load reads and validates gateway.toml.
func (c *commonFlags) load() (*config.Config, error) {
	cfg, err := config.Load(c.paths.Config)
	if err != nil {
		return nil, fmt.Errorf("config error: %w", err)
	}
	return cfg, nil
}

// stage renders the tree into the staging directory.
func (c *commonFlags) stage(cfg *config.Config) ([]render.File, error) {
	return render.Write(cfg, c.paths.Build, render.Options{Repo: c.paths.Repo})
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	quiet := fs.Bool("quiet", false, "print only the summary")
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
	files, err := f.stage(cfg)
	if err != nil {
		return err
	}
	if !*quiet {
		for _, file := range files {
			fmt.Printf("  %s\n", file.Path)
		}
	}
	fmt.Printf("rendered %d files into %s\n", len(files), f.paths.Build)
	return nil
}

func cmdDiff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	asJSON := fs.Bool("json", false, "emit the plan as JSON")
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
	// Always render. Comparing a stale build tree against files installed from
	// that very tree reports "no changes" no matter what you edited, which is
	// worse than no diff at all: it actively tells you your edit did nothing.
	files, err := f.stage(cfg)
	if err != nil {
		return err
	}
	plan, err := apply.Compare(files, apply.Options{Root: f.root})
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(plan)
	}
	printPlan(plan)
	return nil
}

// printPlan renders a plan the way `diff -u` would, one file at a time.
func printPlan(plan *apply.Plan) {
	for _, c := range plan.Pending() {
		switch {
		case c.Status == apply.New:
			fmt.Printf("%s      %s\n", cli.Green("new"), c.Live)
		case c.Binary:
			fmt.Printf("%s  %s (binary)\n", cli.Yellow("changed"), c.Live)
		default:
			fmt.Printf("%s  %s\n", cli.Yellow("changed"), c.Live)
			for _, line := range splitNonEmpty(diffutil.Format(c.Hunks)) {
				fmt.Println("    " + colourDiffLine(line))
			}
		}
	}
	for _, unit := range plan.Stale {
		fmt.Printf("%s  /%s (no longer in the config)\n", cli.Red("remove"), unit)
	}
	if !plan.Changed() {
		cli.Info("no changes")
	}
}

func colourDiffLine(line string) string {
	switch {
	case len(line) > 0 && line[0] == '+':
		return cli.Green(line)
	case len(line) > 0 && line[0] == '-':
		return cli.Red(line)
	case len(line) > 1 && line[0] == '@':
		return cli.Dimmed(line)
	}
	return line
}

func splitNonEmpty(text string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(text); i++ {
		if i == len(text) || text[i] == '\n' {
			if i > start {
				out = append(out, text[start:i])
			}
			start = i + 1
		}
	}
	return out
}
