package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/system"
)

func cmdEnable(args []string) error {
	cli.NeedRoot("enable")
	sd := system.Systemd{}
	if err := sd.EnableStack(); err != nil {
		return err
	}
	if err := sd.Start("gateway.target"); err != nil {
		return err
	}
	cli.Info("gateway.target enabled — the stack now starts on boot")
	return cmdStatus(args)
}

func cmdDisable(args []string) error {
	cli.NeedRoot("disable")
	fs := flag.NewFlagSet("disable", flag.ExitOnError)
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cli.Warn("This stops the tunnel AND the firewall. Proxied clients lose")
	cli.Warn("connectivity entirely; they do not fall back to a direct path.")
	cli.Warn("For a working-but-unproxied LAN, use 'gw panic' instead.")
	if !*yes && !confirm("continue?") {
		return fmt.Errorf("aborted")
	}

	sd := system.Systemd{}
	if err := sd.Stop("gateway.target"); err != nil {
		cli.Warn("%v", err)
	}
	for _, unit := range system.StackUnits {
		_ = sd.Disable(unit)
	}
	cli.Info("gateway.target disabled — nothing will start on the next boot")
	return nil
}

func cmdRestart(args []string) error {
	cli.NeedRoot("restart")
	// PartOf= on each member makes this propagate. tailscaled is excluded on
	// purpose so restarting the stack cannot drop the session you are running
	// this over.
	if err := (system.Systemd{}).Restart("gateway.target"); err != nil {
		return err
	}
	return cmdStatus(args)
}

// journalUnits are followed by `gw logs`: everything that can explain a fault,
// and nothing that cannot.
var journalUnits = []string{"xray", "gw-network", "gw-health", "AdGuardHome", "gw-web"}

func cmdLogs(args []string) error {
	argv := []string{"-f"}
	for _, u := range journalUnits {
		argv = append(argv, "-u", u)
	}
	// Job output is logged with `logger -t gw-job-<name>`, so it has no unit.
	argv = append(argv, "-t", "gw-health")
	argv = append(argv, args...)

	cmd := exec.Command("journalctl", argv...)
	cmd.Stdout, cmd.Stderr, cmd.Stdin = os.Stdout, os.Stderr, os.Stdin
	return cmd.Run()
}

func confirm(question string) bool {
	fmt.Printf("%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
