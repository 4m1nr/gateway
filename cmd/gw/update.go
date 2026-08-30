package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/am1nr/gateway/internal/cli"
)

// helperDir is where `gw apply` installs the update scripts. Each one downloads,
// verifies, tests the new artefact against the LIVE config, and rolls back if
// the service does not come up — which is why they are invoked rather than
// reimplemented inline.
const helperDir = "/usr/local/lib/gateway"

// aptProxyConf is written and removed around the commands that need it.
//
// Only relevant before the tunnel exists. apt has no SOCKS support of its own
// beyond this setting, and leaving it configured permanently would break apt the
// day the bootstrap proxy goes away.
const aptProxyConf = "/etc/apt/apt.conf.d/99-gw-bootstrap-proxy"

func cmdUpdate(args []string) error {
	cli.NeedRoot("update")

	what := "all"
	if len(args) > 0 {
		what = args[0]
		args = args[1:]
	}
	version := ""
	if len(args) > 0 {
		version = args[0]
	}

	switch what {
	case "--check", "check":
		return updateCheck()
	case "xray":
		return helper("xray-update.sh", orLatest(version))
	case "adguard", "adguardhome":
		return helper("adguard-update.sh", orLatest(version))
	case "tailscale":
		// apt-managed, so it follows the distro package rather than a release.
		return withAptProxy(func() error {
			if err := apt("update", "-qq"); err != nil {
				return err
			}
			return apt("-y", "install", "--only-upgrade", "tailscale")
		})
	case "geo", "geodata":
		// Go, not a helper script: geodata can have several sources now, which
		// a flat env file cannot describe.
		if version == "--force" || version == "force" {
			return cmdGeoUpdate([]string{"--force"})
		}
		return cmdGeoUpdate(nil)
	case "packages", "apt":
		return withAptProxy(func() error {
			if err := apt("update", "-qq"); err != nil {
				return err
			}
			return apt("-y", "upgrade")
		})
	case "services":
		// What the scheduled updater runs by default: the three things nothing
		// else keeps current, each of which tests itself and rolls back. apt is
		// left to unattended-upgrades, which does security only — an unattended
		// full `apt upgrade` on the box the whole house routes through is a
		// bigger bet than a binary that reverts when it fails to start.
		updateServices()
		return nil
	case "all":
		// Ordered least- to most-disruptive, and each step is survivable on its
		// own: geodata rolls back, both binaries roll back, apt is apt.
		updateServices()
		cli.Info("updating packages")
		if err := withAptProxy(func() error {
			if err := apt("update", "-qq"); err != nil {
				return err
			}
			return apt("-y", "upgrade")
		}); err != nil {
			cli.Warn("package update failed: %v", err)
		}
		cli.Info("re-applying config")
		return cmdApply(nil)
	}

	return fmt.Errorf(`unknown update target: %s
  try: all | services | xray [version] | adguard [version] | tailscale | geo | packages | --check`, what)
}

func orLatest(v string) string {
	if v == "" {
		return "latest"
	}
	return v
}

// updateServices runs the three self-testing updaters, reporting rather than
// aborting: one failing should not stop the others.
func updateServices() {
	cli.Info("updating geodata")
	if err := cmdGeoUpdate(nil); err != nil {
		cli.Warn("geodata update failed: %v", err)
	}
	cli.Info("updating Xray")
	if err := helper("xray-update.sh", "latest"); err != nil {
		cli.Warn("Xray update failed: %v", err)
	}
	if _, err := os.Stat("/opt/AdGuardHome/AdGuardHome"); err == nil {
		cli.Info("updating AdGuard Home")
		if err := helper("adguard-update.sh", "latest"); err != nil {
			cli.Warn("AdGuard update failed: %v", err)
		}
	}
}

// updateCheck reports what is available and changes nothing, so it is safe from
// a cron job or just to see where you stand.
func updateCheck() error {
	for _, c := range []struct{ label, script string }{
		{"xray", "xray-update.sh"},
		{"adguard", "adguard-update.sh"},
	} {
		fmt.Printf("%s\n", cli.Green("--- "+c.label+" ---"))
		if err := helper(c.script, "--check"); err != nil {
			cli.Warn("%v", err)
		}
	}
	fmt.Printf("%s\n", cli.Green("--- geodata ---"))
	if err := cmdGeoUpdate([]string{"--check"}); err != nil {
		cli.Warn("%v", err)
	}

	fmt.Printf("%s\n", cli.Green("--- packages ---"))
	_ = withAptProxy(func() error {
		_ = apt("update", "-qq")
		out, err := exec.Command("apt-get", "-s", "upgrade").Output()
		if err != nil {
			fmt.Println("unknown")
			return nil
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, " upgraded") && strings.Contains(line, " newly installed") {
				fmt.Println(strings.TrimSpace(line))
				return nil
			}
		}
		fmt.Println("unknown")
		return nil
	})

	if _, err := exec.LookPath("tailscale"); err == nil {
		fmt.Printf("%s\n", cli.Green("--- tailscale ---"))
		out, _ := exec.Command("tailscale", "version").Output()
		if line, _, _ := strings.Cut(string(out), "\n"); line != "" {
			fmt.Println(line)
		}
	}
	return nil
}

// helper runs one of the installed update scripts, streaming its output.
func helper(script string, args ...string) error {
	path := helperDir + "/" + script
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("%s is not installed — run `sudo gw apply` first", path)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	// The updaters need the bootstrap proxy too, and they read it from the
	// rendered env file themselves.
	cmd.Env = append(os.Environ(), "GW_PROXY="+os.Getenv("GW_PROXY"))
	return cmd.Run()
}

func apt(args ...string) error {
	cmd := exec.Command("apt-get", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	return cmd.Run()
}

// withAptProxy writes the apt proxy config around fn and removes it after,
// whatever happens.
func withAptProxy(fn func() error) error {
	proxy := os.Getenv("GW_PROXY")
	if proxy == "" {
		proxy = cli.Env(helperDir + "/env")["BOOTSTRAP_PROXY"]
	}
	if proxy == "" {
		return fn()
	}

	cli.Info("using the bootstrap proxy for apt: %s", proxy)
	body := fmt.Sprintf("// Written by `gw` for this command only; removed when it finishes.\n"+
		"Acquire::http::Proxy %q;\nAcquire::https::Proxy %q;\n", proxy, proxy)
	if err := os.WriteFile(aptProxyConf, []byte(body), 0o644); err != nil {
		return fmt.Errorf("writing the apt proxy config: %w", err)
	}
	defer os.Remove(aptProxyConf)
	return fn()
}
