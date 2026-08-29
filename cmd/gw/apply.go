package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/am1nr/gateway/internal/apply"
	"github.com/am1nr/gateway/internal/cli"
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
		if err := postInstall(f, cfg.WebEnabled); err != nil {
			return err
		}
	}
	cli.Info("applied")
	return nil
}

// postInstall does the parts of apply that only make sense against the live
// system and have no meaning under --root.
func postInstall(f commonFlags, webEnabled bool) error {
	sd := system.Systemd{}

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
	return nil
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
