package action

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Command is a gw subcommand the dashboard may run.
type Command struct {
	Name string `json:"name"`
	// Summary is what it does, in the dashboard's words.
	Summary string `json:"summary"`
	// Args are the fixed arguments. Nothing from the request is ever appended
	// except a value matched against Choices below.
	Args []string `json:"args,omitempty"`
	// Disruptive marks a command that interrupts service. The UI confirms these
	// separately; nothing here treats them differently, because a confirmation
	// the server enforces is one the server has to define, and this one cannot
	// know whether the person meant it.
	Disruptive bool `json:"disruptive"`
	// Timeout bounds it.
	Timeout time.Duration `json:"-"`
	// Argument, when set, names a single free argument the command accepts,
	// validated by Validate.
	Argument string `json:"argument,omitempty"`
	// Validate checks that argument. nil means the command takes none.
	Validate func(string) error `json:"-"`
}

// commands is the whole surface the dashboard can run.
//
// A whitelist of fixed argument lists, not a command line. The dashboard
// already reaches root — it can schedule a root cron job — so this does not
// raise the privilege ceiling, but "run gw with whatever an HTTP request says"
// and "run one of these nineteen things" are still different grants, and only
// one of them can be reviewed.
var commands = map[string]Command{
	"status": {Name: "status", Summary: "Services, boot state, tunnel state and killswitch drops", Args: []string{"status"}, Timeout: 30 * time.Second},
	"check":  {Name: "check", Summary: "End-to-end verification of the whole path", Args: []string{"check"}, Timeout: 5 * time.Minute},
	"check-killswitch": {
		Name: "check-killswitch", Summary: "Also prove traffic dies rather than leaking",
		Args: []string{"check", "--killswitch"}, Disruptive: true, Timeout: 5 * time.Minute,
	},
	"diff":    {Name: "diff", Summary: "What apply would change", Args: []string{"diff"}, Timeout: time.Minute},
	"apply":   {Name: "apply", Summary: "Render, validate, install and reload", Args: []string{"apply"}, Disruptive: true, Timeout: 6 * time.Minute},
	"render":  {Name: "render", Summary: "Generate build/ without changing anything", Args: []string{"render"}, Timeout: time.Minute},
	"diag":    {Name: "diag", Summary: "Why a client's traffic is or is not intercepted", Args: []string{"diag"}, Argument: "client IP", Validate: validateClientIP, Timeout: time.Minute},
	"history": {Name: "history", Summary: "What happened while you were not looking", Args: []string{"history"}, Argument: "hours", Validate: validateHours, Timeout: 2 * time.Minute},
	"bench":   {Name: "bench", Summary: "Find the throughput bottleneck: link, CPU or tunnel", Args: []string{"bench"}, Disruptive: true, Timeout: 6 * time.Minute},
	"logs":    {Name: "logs", Summary: "Recent journal entries from every relevant unit", Args: []string{"logs", "--no-pager", "-n", "200"}, Timeout: time.Minute},

	"restart": {Name: "restart", Summary: "Restart the whole stack", Args: []string{"restart"}, Disruptive: true, Timeout: 3 * time.Minute},
	"enable":  {Name: "enable", Summary: "Make the stack start on boot", Args: []string{"enable"}, Timeout: time.Minute},

	"update-check":    {Name: "update-check", Summary: "What updates are available; changes nothing", Args: []string{"update", "--check"}, Timeout: 5 * time.Minute},
	"update-services": {Name: "update-services", Summary: "Geodata, Xray and AdGuard, each rolling back if it fails", Args: []string{"update", "services"}, Disruptive: true, Timeout: 20 * time.Minute},
	"update-geo":      {Name: "update-geo", Summary: "Routing data only", Args: []string{"update", "geo"}, Timeout: 10 * time.Minute},
	"update-xray":     {Name: "update-xray", Summary: "Xray, tested against the live config before it replaces anything", Args: []string{"update", "xray"}, Disruptive: true, Timeout: 15 * time.Minute},
	"update-adguard":  {Name: "update-adguard", Summary: "AdGuard Home, with the same rollback", Args: []string{"update", "adguard"}, Disruptive: true, Timeout: 15 * time.Minute},

	"version": {Name: "version", Summary: "Which build is running", Args: []string{"version"}, Timeout: 15 * time.Second},
}

// deliberatelyAbsent records what the dashboard cannot run, and why. Keeping
// the reasoning next to the list is what stops someone adding one back without
// noticing the problem.
//
//	panic    removes the killswitch and lets everything out unproxied. It is
//	         the command you run when you have lost confidence in the gateway,
//	         which is exactly when you should be at a console rather than in
//	         its web UI.
//	disable  stops the firewall and the tunnel. A proxied client does not fall
//	         back to a direct path; it simply loses the internet, including
//	         whoever pressed the button.
//	trace    streams until interrupted, and leaves a rule behind if the stream
//	         is dropped rather than closed.
//	init     an interactive interview that rewrites the config from scratch.
//	web-passwd  reads a password from a terminal; it exists to be run on the box.
var deliberatelyAbsent = []string{"panic", "disable", "trace", "init", "web-passwd"}

// AvailableCommands lists what the dashboard may run, for the UI to render.
func AvailableCommands() []Command {
	out := make([]Command, 0, len(commands))
	for _, c := range commands {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (h Handler) commandList() Response {
	return ok(map[string]any{
		"commands": AvailableCommands(),
		"excluded": deliberatelyAbsent,
	})
}

// runCommand executes one whitelisted command and returns its output.
func (h Handler) runCommand(req Request) Response {
	cmd, known := commands[req.Command]
	if !known {
		return fail("%q is not a command the dashboard may run", req.Command)
	}

	args := append([]string(nil), cmd.Args...)
	if cmd.Validate != nil {
		// Exactly one free argument, validated by the command's own rule.
		// Anything else the request carries is ignored rather than appended.
		if len(req.Args) > 1 {
			return fail("%s takes at most one argument", cmd.Name)
		}
		if len(req.Args) == 1 && req.Args[0] != "" {
			if err := cmd.Validate(req.Args[0]); err != nil {
				return fail("%v", err)
			}
			args = append(args, req.Args[0])
		}
	} else if len(req.Args) > 0 {
		return fail("%s takes no arguments", cmd.Name)
	}

	binary := filepath.Join(h.Repo, "bin", "gw")
	if _, err := os.Stat(binary); err != nil {
		return fail("%s is not built — run `go build -o bin/gw ./cmd/gw` on the box", binary)
	}

	timeout := cmd.Timeout
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Argument slice, never a shell. The only value that is not a constant has
	// already been through the command's own validator.
	run := exec.CommandContext(ctx, binary, args...)
	run.Env = append(os.Environ(), "GW_REPO="+h.Repo, "GW_CONFIG="+h.Config, "NO_COLOR=1")
	var out bytes.Buffer
	run.Stdout, run.Stderr = &out, &out
	err := run.Run()

	body := out.String()
	// Bounded: some of these are chatty, and the whole thing crosses a pipe to
	// a network-facing process.
	const maxOutput = 256 * 1024
	if len(body) > maxOutput {
		body = "… (earlier output trimmed) …\n" + body[len(body)-maxOutput:]
	}

	status := "ok"
	switch {
	case ctx.Err() != nil:
		status = "timeout"
		body += fmt.Sprintf("\n\ngw %s did not finish within %s and was stopped.",
			strings.Join(args, " "), timeout)
	case err != nil:
		status = "failed"
	}

	// A non-zero exit is a result, not a transport failure: `gw check` exits 1
	// when a check fails, and the output is the whole point.
	return ok(map[string]any{
		"command": cmd.Name,
		"args":    args,
		"status":  status,
		"output":  body,
	})
}

// ------------------------------------------------------------- validators --

func validateClientIP(v string) error {
	if _, err := netipParse(v); err != nil {
		return fmt.Errorf("%q is not a valid IP address", v)
	}
	return nil
}

func validateHours(v string) error {
	n, err := atoiPositive(v)
	if err != nil || n < 1 || n > 720 {
		return fmt.Errorf("hours must be a whole number between 1 and 720, not %q", v)
	}
	return nil
}

// netipParse and atoiPositive keep the validators to one obvious line each.
func netipParse(v string) (any, error) {
	return netip.ParseAddr(strings.TrimSpace(v))
}

func atoiPositive(v string) (int, error) {
	return strconv.Atoi(strings.TrimSpace(v))
}
