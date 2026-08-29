package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/am1nr/gateway/internal/config/edit"
)

func cmdJob(args []string) error {
	fs := flag.NewFlagSet("job", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	asJSON := fs.Bool("json", false, "emit the job list as JSON")
	user := fs.String("user", "root", "user the job runs as")
	desc := fs.String("desc", "", "one-line description")
	file := fs.String("file", "", "read the script from this file, or - for stdin")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}

	rest := fs.Args()
	if len(rest) == 0 {
		return fmt.Errorf("usage: gw job <list|add|rm|enable|disable> ...")
	}

	switch rest[0] {
	case "list":
		return jobList(f, *asJSON)
	case "add":
		if len(rest) < 3 {
			return fmt.Errorf(`usage: gw job add <name> <schedule> [--user U] [--desc D] [--file script.sh | -]
  e.g. gw job add nightly "0 4 * * *" --file backup.sh
       echo 'reboot' | gw job add weekly-reboot @weekly --file -`)
		}
		script, err := readScript(*file)
		if err != nil {
			return err
		}
		if err := edit.SaveJob(f.paths.Config, edit.Job{
			Name: rest[1], Schedule: rest[2], Script: script,
			User: *user, Enabled: true, Description: *desc,
		}); err != nil {
			return err
		}
		fmt.Printf("job %q scheduled: %s (as %s)\n", rest[1], rest[2], *user)
		fmt.Println("run `sudo gw apply` to install it")
		return nil
	case "rm":
		if len(rest) != 2 {
			return fmt.Errorf("usage: gw job rm <name>")
		}
		if err := edit.RemoveJob(f.paths.Config, rest[1]); err != nil {
			return err
		}
		fmt.Printf("removed %q; run `sudo gw apply` to make it live\n", rest[1])
		return nil
	case "enable", "disable":
		if len(rest) != 2 {
			return fmt.Errorf("usage: gw job %s <name>", rest[0])
		}
		on := rest[0] == "enable"
		if err := edit.ToggleJob(f.paths.Config, rest[1], on); err != nil {
			return err
		}
		fmt.Printf("%q %sd; run `sudo gw apply` to make it live\n", rest[1], rest[0])
		return nil
	}
	return fmt.Errorf("unknown subcommand: %s", rest[0])
}

// readScript takes the script from a file or stdin. It never comes from argv: a
// job script is arbitrary text and belongs nowhere near a command line.
func readScript(file string) (string, error) {
	if file == "" || file == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("reading the script from stdin: %w", err)
		}
		return string(data), nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("--file: %w", err)
	}
	return string(data), nil
}

func jobList(f commonFlags, asJSON bool) error {
	jobs, err := edit.Jobs(f.paths.Config)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if jobs == nil {
			jobs = []edit.Job{}
		}
		return enc.Encode(jobs)
	}
	if len(jobs) == 0 {
		fmt.Println("no scheduled jobs")
		return nil
	}
	width := 0
	for _, j := range jobs {
		width = max(width, len(j.Name))
	}
	for _, j := range jobs {
		state := "  "
		if !j.Enabled {
			state = "off"
		}
		where := ""
		if !j.Managed {
			where = "  (hand-written)"
		}
		summary := j.Description
		if summary == "" {
			if first, _, _ := strings.Cut(strings.TrimSpace(j.Script), "\n"); first != "" {
				summary = first
			}
		}
		fmt.Printf("%-*s  %s  %-14s %-8s %s%s\n",
			width, j.Name, state, j.Schedule, j.User, summary, where)
	}
	return nil
}
