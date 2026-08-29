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
	"path/filepath"
	"strings"

	"github.com/am1nr/gateway/internal/buildinfo"
	"github.com/am1nr/gateway/internal/cli"
)

// version is an optional -ldflags stamp naming a release. Left at "dev", the
// binary takes its identity from the VCS information Go records automatically,
// so no build path can forget to stamp it.
var version = "dev"

// build is resolved once, against the checkout this binary belongs to.
func build() buildinfo.Info {
	repo := ""
	if paths, err := cli.Resolve(); err == nil {
		repo = paths.Repo
	}
	return buildinfo.Resolve(version, repo)
}

// ensurePath puts the sbin directories on PATH.
//
// nft, sysctl, ip, visudo and useradd all live in /usr/sbin, which is NOT in
// every root PATH — a plain `su`, or a root shell whose profile never added it,
// has only /usr/bin. Calling them by bare name then fails in ways that look
// like something else entirely: `gw status` reported "firewall not loaded"
// purely because it could not find nft, while `sudo gw apply` worked, because
// sudo's secure_path does include /usr/sbin. The disagreement looked like the
// firewall was vanishing.
func ensurePath() {
	want := []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	have := map[string]bool{}
	current := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(current) {
		have[dir] = true
	}
	var missing []string
	for _, dir := range want {
		if !have[dir] {
			missing = append(missing, dir)
		}
	}
	if len(missing) == 0 {
		return
	}
	// Prepended, so the expected tool wins over a same-named one further along
	// a PATH this process did not choose.
	joined := strings.Join(missing, string(filepath.ListSeparator))
	if current != "" {
		joined += string(filepath.ListSeparator) + current
	}
	_ = os.Setenv("PATH", joined)
}

// actionHelperName is the filename `gw apply` installs the privileged helper
// under. The sudoers grant names that exact path with NO arguments — that is
// the security property, and it is why the helper has to recognise itself by
// the name it was invoked as rather than by a subcommand it can never be given.
const actionHelperName = "gw-action"

func main() {
	ensurePath()

	args := os.Args[1:]

	// Invoked as gw-action, this process IS the privileged helper, whatever
	// arguments it did or did not receive. Without this it printed usage and
	// exited 0 without reading the request on stdin, so every dashboard action
	// failed and the login page reported it as "no password set".
	if filepath.Base(os.Args[0]) == actionHelperName {
		if err := cmdWebAction(args); err != nil {
			cli.Errorf("%v", err)
			os.Exit(1)
		}
		return
	}

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
	case "diag":
		err = cmdDiag(rest)
	case "trace":
		err = cmdTrace(rest)
	case "history":
		err = cmdHistory(rest)
	case "bench":
		err = cmdBench(rest)
	case "update":
		err = cmdUpdate(rest)
	case "panic":
		err = cmdPanic(rest)
	case "init":
		err = cmdInit(rest)
	case "check":
		err = cmdCheck(rest)
	case "version", "--version", "-v":
		info := build()
		fmt.Println(info)
		if warning := info.StaleWarning(); warning != "" {
			cli.Warn("%s", warning)
		}
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
  gw init          interview -> gateway.toml (parses a share link)
  gw check         end-to-end verification, including leak tests
  gw diag [ip]     why a client's traffic is or is not being intercepted
  gw trace <ip>    follow one client's packets rule by rule, live
  gw history [h]   what happened while you were not looking
  gw bench         find the throughput bottleneck: link, CPU, or tunnel
  gw update        all | services | xray | adguard | tailscale | geo | packages | --check
  gw panic         drop to plain NAT so the LAN works while you debug
  gw web-passwd    set the dashboard password
  gw version       which build is running

Flags:
  --config PATH    gateway.toml to read (default: <repo>/gateway.toml)
  --out PATH       staging tree to write (default: <repo>/build)
`)
}
