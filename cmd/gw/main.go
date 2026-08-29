// Command gw is the only command you should need on this box.
//
//	gw render        generate build/ from gateway.toml (safe, no changes)
//	gw diff          show what apply would change
//	gw apply         render, diff, validate, install, reload
//	gw enable        enable the whole stack to start on boot
//	gw disable       stop the stack and remove it from boot
//	gw restart       restart the whole stack
//	gw client        add/remove/list per-client policy
//	gw job           add/remove/list scheduled jobs
//	gw status        what is running and whether the tunnel is up
//	gw logs          follow the relevant journals
package main

import (
	"fmt"
	"os"

	"github.com/am1nr/gateway/internal/cli"
)

// version is stamped by the build. It answers "which code is actually
// running?", which matters because a stale copy of the binary survives every
// git pull and makes each fix you pull look like it did nothing.
var version = "dev"

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		usage()
		os.Exit(0)
	}

	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "render":
		err = cmdRender(rest)
	case "diff":
		err = cmdDiff(rest)
	case "apply":
		err = cmdApply(rest)
	case "client":
		err = cmdClient(rest)
	case "job":
		err = cmdJob(rest)
	case "status":
		err = cmdStatus(rest)
	case "enable":
		err = cmdEnable(rest)
	case "disable":
		err = cmdDisable(rest)
	case "restart":
		err = cmdRestart(rest)
	case "logs":
		err = cmdLogs(rest)
	case "web":
		err = cmdWeb(rest)
	case "web-action":
		err = cmdWebAction(rest)
	case "web-passwd":
		err = cmdWebPasswd(rest)
	case "version", "--version", "-v":
		fmt.Println(version)
	case "help", "--help", "-h":
		usage()
	default:
		cli.Errorf("unknown command: %s (try: gw help)", cmd)
		os.Exit(1)
	}
	if err != nil {
		cli.Errorf("%v", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`gw — the only command you should need on this box.

  gw render        generate build/ from gateway.toml (safe, no changes)
  gw diff          show what apply would change
  gw apply         render, diff, validate, install, reload
  gw client        add/remove/list per-client policy
  gw job           add/remove/list scheduled jobs
  gw status        services, boot state, tunnel state, killswitch drops
  gw enable        enable the whole stack to start on boot
  gw disable       stop the stack and remove it from boot
  gw restart       restart the whole stack
  gw logs          follow every relevant journal at once
  gw web-passwd    set the dashboard password
  gw version       which build is running

Flags:
  --config PATH    gateway.toml to read (default: <repo>/gateway.toml)
  --out PATH       staging tree to write (default: <repo>/build)
`)
}
