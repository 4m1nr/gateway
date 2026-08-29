package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/am1nr/gateway/internal/adguard"
	"github.com/am1nr/gateway/internal/apply"
	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/jsonx"
	"github.com/am1nr/gateway/internal/render"
	"github.com/am1nr/gateway/internal/system"
)

func cmdApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	var f commonFlags
	f.bind(fs)
	dryRun := fs.Bool("dry-run", false, "validate and show the diff, write nothing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := f.resolve(); err != nil {
		return err
	}
	// --root exists for exercising the install path against a throwaway
	// directory; only touching the real filesystem needs root.
	if f.root == "/" {
		cli.NeedRoot("apply")
	}

	cfg, err := f.load()
	if err != nil {
		return err
	}

	cli.Info("rendering from %s", f.paths.Config)
	files, err := f.stage(cfg)
	if err != nil {
		return err
	}

	plan, err := apply.Compare(files, apply.Options{Root: f.root})
	if err != nil {
		return err
	}
	cli.Info("changes to be applied:")
	printPlan(plan)

	var sys apply.System
	if f.root == "/" {
		sys = system.Systemd{}
	}

	_, err = apply.Run(apply.Request{
		Files:    files,
		StageDir: f.paths.Build,
		DryRun:   *dryRun,
		Options:  apply.Options{Root: f.root},
		System:   sys,
		Report: func(s apply.Step) {
			if s.Detail == "" {
				cli.Info("%s", s.Name)
			} else {
				cli.Info("%s: %s", s.Name, s.Detail)
			}
		},
	})
	if err != nil {
		var ve *apply.ValidationError
		if errors.As(err, &ve) {
			// Nothing was written, and saying so is the whole point: the reader
			// needs to know the box is still in its previous state.
			cli.Errorf("%v", ve)
			return errors.New("nothing was installed or reloaded")
		}
		return err
	}

	if *dryRun {
		cli.Info("dry run — nothing written")
		return nil
	}

	if f.root == "/" {
		if err := postInstall(f, cfg); err != nil {
			return err
		}
	}
	cli.Info("applied")
	return nil
}

// adguardYAML is AdGuard Home's own config, which it owns and rewrites.
const adguardYAML = "/opt/AdGuardHome/AdGuardHome.yaml"

// postInstall does the parts of apply that only make sense against the live
// system and have no meaning under --root.
func postInstall(f commonFlags, cfg *config.Config) error {
	sd := system.Systemd{}
	webEnabled := cfg.WebEnabled

	// Debian's nftables.service loads /etc/nftables.conf, which begins with
	// `flush ruleset` — it would wipe our table out from under gw-network,
	// which stays "active" (Type=oneshot, RemainAfterExit) while its rules
	// quietly vanish. Two units cannot both own the ruleset; gw-network does.
	if sd.Exists("nftables.service") {
		if sd.IsEnabled("nftables.service") == "enabled" || sd.IsActive("nftables.service") == "active" {
			cli.Warn("nftables.service is active or enabled; it flushes the whole ruleset.")
			cli.Warn("Masking it — gw-network manages /etc/nftables.d/gateway.nft instead.")
			_ = sd.Disable("nftables.service")
			_ = sd.Mask("nftables.service")
		}
	}

	// Keep /usr/local/bin/gw pointing INTO the repo. If it is a copy instead of
	// a symlink, `git pull` updates the checkout and changes nothing about the
	// command you actually run: every fix you pull looks like it did not work,
	// and the only evidence is that the output never changes.
	link := "/usr/local/bin/gw"
	target := filepath.Join(f.paths.Repo, "bin", "gw")
	if err := ensureSymlink(link, target); err != nil {
		cli.Warn("%v", err)
	}

	if webEnabled {
		// The dashboard's privileged helper is a copy of this binary, installed
		// root-owned outside the repo. The sudoers grant names that exact path
		// with no arguments, so a compromised web process cannot ask for
		// anything else.
		if err := installActionHelper(); err != nil {
			cli.Warn("could not install the privileged helper: %v", err)
		}
	}

	if sd.Exists("xray.service") {
		cli.Info("restarting Xray")
		if err := sd.Restart("xray.service"); err != nil {
			cli.Warn("%v", err)
		}
	} else {
		cli.Warn("xray is not installed yet — run scripts/10-xray.sh")
	}

	// AdGuard's settings are merged rather than templated, because AdGuard owns
	// that file and rewrites it.
	if _, err := os.Stat(adguardYAML); err == nil {
		cli.Info("merging AdGuard Home settings")
		overrides, err := adguardOverrides(cfg)
		if err != nil {
			cli.Warn("%v", err)
		} else if err := adguard.Merge(adguardYAML, overrides); err != nil {
			cli.Warn("%v", err)
		} else {
			_ = sd.Restart("AdGuardHome.service")
		}
	} else {
		cli.Warn("AdGuard Home is not set up yet — run scripts/20-adguard.sh")
	}

	// `gw panic` leaves a blanket-masquerade table behind. Applying a real
	// config must remove it, or the box keeps a stale NAT path that nothing in
	// the generated ruleset knows about.
	clearPanicTable()

	// It may also have pointed the resolver at the router. Undone only once
	// AdGuard actually answers.
	restoreResolverAfterApply()

	if err := sd.Start("gateway.target"); err != nil {
		cli.Warn("%v", err)
	}
	return nil
}

// adguardOverrides renders the settings block and decodes it into the shape the
// YAML merge wants.
func adguardOverrides(cfg *config.Config) (map[string]any, error) {
	raw, err := jsonx.EncodeIndented(render.AdGuardOverrides(cfg))
	if err != nil {
		return nil, fmt.Errorf("building the AdGuard settings: %w", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("building the AdGuard settings: %w", err)
	}
	return out, nil
}

// clearPanicTable removes the table `gw panic` installs, if it is there.
func clearPanicTable() {
	if exec.Command("nft", "list", "table", "ip", "gwpanic").Run() != nil {
		return
	}
	cli.Info("clearing the panic-mode NAT table")
	if err := exec.Command("nft", "delete", "table", "ip", "gwpanic").Run(); err != nil {
		cli.Warn("could not remove the panic table: %v", err)
	}
}

func ensureSymlink(link, target string) error {
	current, err := os.Readlink(link)
	if err == nil && current == target {
		return nil
	}
	if st, statErr := os.Lstat(link); statErr == nil && st.Mode()&os.ModeSymlink == 0 {
		// A copy has been surviving every pull. Move it aside rather than
		// deleting it, and say so.
		if err := os.Rename(link, link+".bak"); err != nil {
			return fmt.Errorf("%s is a copy, not a symlink, and could not be moved aside: %w", link, err)
		}
		cli.Warn("%s was a copy, not a symlink — it has been surviving your pulls", link)
		cli.Warn("the old copy is at %s.bak", link)
	} else if statErr == nil {
		if err := os.Remove(link); err != nil {
			return err
		}
	}
	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("linking %s -> %s: %w", link, target, err)
	}
	cli.Info("%s -> %s", link, target)
	return nil
}

// actionHelperPath is where the dashboard's privileged helper is installed. It
// is named verbatim in the sudoers grant, so it must not move without the
// template moving with it.
const actionHelperPath = "/usr/local/lib/gateway/gw-action"

func installActionHelper() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(actionHelperPath), 0o755); err != nil {
		return err
	}
	// Written through a temporary file: replacing a running helper's inode in
	// place is how you get a partially-written setuid-adjacent binary.
	tmp := actionHelperPath + ".new"
	if err := os.WriteFile(tmp, data, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	return os.Rename(tmp, actionHelperPath)
}
