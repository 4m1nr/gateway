package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/diag"
)

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	asJSON := fs.Bool("json", false, "emit the status as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}

	s := diag.Collector{Root: f.root}.Collect()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	printStatus(f, s)
	return nil
}

func printStatus(f commonFlags, s diag.Status) {
	switch s.Tunnel {
	case diag.Up:
		fmt.Printf("gateway     %s (intercepted traffic reaches the tunnel)\n", cli.Green("OK"))
	case diag.Degraded:
		// The distinction that matters: Xray is fine, the packets are not
		// getting to it. Reporting this as "tunnel down" sends you to the wrong
		// half of the system.
		fmt.Printf("gateway     %s — tunnel up, interception broken (%d failed probes)\n",
			cli.Red("DEGRADED"), s.Fails)
	case diag.Down:
		fmt.Printf("gateway     %s (%d consecutive failed probes)\n", cli.Red("DOWN"), s.Fails)
	default:
		fmt.Printf("gateway     %s (health check has not run yet)\n", cli.Yellow("unknown"))
	}
	if s.Detail != "" {
		cli.Dim("  %s", s.Detail)
	}
	if s.Lifeline {
		fmt.Printf("lifeline    %s — tailscaled is bypassing the tunnel\n", cli.Yellow("ENGAGED"))
	}

	// Which code is actually running. bin/gw is a build artefact, so a git pull
	// updates the checkout and leaves the binary alone — every fix you pull
	// then appears to have done nothing, and the only evidence is that the
	// output never changes.
	info := build()
	cli.Dim("version     %s  %s", info, f.paths.Repo)
	if warning := info.StaleWarning(); warning != "" {
		cli.Warn("%s", warning)
	}
	warnIfStaleBinary(f)

	for _, u := range s.Units {
		state := u.Active
		if u.Active != "active" {
			state = cli.Yellow(u.Active)
		}
		fmt.Printf("%-11s %s (boot: %s)\n",
			strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(
				u.Name, ".service"), ".target"), ".timer"),
			state, u.Enabled)
	}

	// A restart is invisible after the fact and is itself an outage: it drops
	// every live connection on every client. A client that "lost the internet
	// for a moment" next to an xray up for four minutes is the explanation.
	if age := s.System.XrayUptimeSec; age > 0 {
		if age < 900 {
			fmt.Printf("%-11s %s — anything connected before that was dropped\n",
				"xray up", cli.Yellow(fmt.Sprintf("started %dm %ds ago", age/60, age%60)))
		} else {
			cli.Dim("%-11s %dh %dm", "xray up", age/3600, (age%3600)/60)
		}
	}

	if s.Firewall.Loaded {
		fmt.Println("firewall    loaded")
		cli.Dim("  default         : %s (any device whose gateway is this box)", s.DefaultPolicy)
		cli.Dim("  intercepted     : %s", orNone(s.Firewall.ProxyClients))
		if len(s.Profiles) > 0 {
			cli.Dim("  profiles        : %s", strings.Join(s.Profiles, ", "))
		}
		cli.Dim("  killswitch drops: %d", s.Firewall.KillswitchDrops)
	} else {
		fmt.Printf("firewall    %s\n", cli.Red("not loaded"))
	}

	if len(s.Traffic) > 0 {
		fmt.Println("traffic     (since Xray last started)")
		for tag, t := range s.Traffic {
			cli.Dim("  %-14s ↑ %s  ↓ %s", tag, humanBytes(t.Uplink), humanBytes(t.Downlink))
		}
	}

	sys := s.System
	cli.Dim("system      up %s · load %.2f · mem %s/%s · disk %s free",
		humanDuration(sys.Uptime), firstLoad(sys.Load),
		humanBytes(sys.MemTotal-sys.MemAvailable), humanBytes(sys.MemTotal),
		humanBytes(sys.DiskFree))
}

func warnIfStaleBinary(f commonFlags) {
	const link = "/usr/local/bin/gw"
	resolved, err := filepath.EvalSymlinks(link)
	if err != nil {
		return
	}
	want, err := filepath.EvalSymlinks(filepath.Join(f.paths.Repo, "bin", "gw"))
	if err != nil || resolved == want {
		return
	}
	cli.Warn("%s is not %s/bin/gw — you are running a stale copy, and", link, f.paths.Repo)
	cli.Warn("git pull will not change it. Fix: sudo ln -sfn %s/bin/gw %s", f.paths.Repo, link)
}

func orNone(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func firstLoad(load []float64) float64 {
	if len(load) == 0 {
		return 0
	}
	return load[0]
}

func humanBytes(n int64) string {
	if n <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f, i := float64(n), 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

func humanDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}
