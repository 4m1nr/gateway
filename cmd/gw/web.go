package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"syscall"

	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/system"
	"github.com/am1nr/gateway/internal/web"
	"github.com/am1nr/gateway/internal/web/action"
	"github.com/am1nr/gateway/internal/webauth"
	"golang.org/x/term"
)

// webSettingsPath is where `gw apply` renders the dashboard's settings.
const webSettingsPath = "/etc/gateway/web.json"

// cmdWeb runs the dashboard. Invoked by gw-web.service as the gwweb user; it
// must never be run as root, because its whole security model is that it is
// not.
func cmdWeb(args []string) error {
	fs := flag.NewFlagSet("web", flag.ExitOnError)
	settingsPath := fs.String("settings", webSettingsPath, "path to web.json")
	helper := fs.String("helper", web.ActionHelperPath, "path to the privileged helper")
	if err := fs.Parse(args); err != nil {
		return err
	}

	raw, err := os.ReadFile(*settingsPath)
	if err != nil {
		return fmt.Errorf("cannot read %s: %w (run `sudo gw apply`)", *settingsPath, err)
	}
	var settings web.Settings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return fmt.Errorf("%s is not valid JSON: %w", *settingsPath, err)
	}
	if len(settings.AllowCIDRs) == 0 {
		return fmt.Errorf("%s lists no allow_cidrs, which would refuse every "+
			"request. Run `sudo gw apply`", *settingsPath)
	}

	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv := web.New(settings, log)
	srv.Privileged = web.SudoCaller{HelperPath: *helper}
	srv.Version = build().Short()

	scheme := "http"
	if settings.TLS {
		scheme = "https"
	}
	addr := fmt.Sprintf("%s:%d", settings.Listen, settings.Port)
	log.Info("dashboard listening",
		"url", fmt.Sprintf("%s://%s", scheme, addr),
		"allow_cidrs", settings.AllowCIDRs)

	return srv.ListenAndServe(addr)
}

// cmdWebAction is the privileged helper: the ONLY thing the web process may
// sudo. It reads one JSON request on stdin and writes one JSON response.
//
// Every field is re-validated here, as root, so a compromised web process
// cannot widen what it is allowed to ask for.
func cmdWebAction(args []string) error {
	if err := action.Must(); err != nil {
		// Reported as JSON so the caller sees a structured refusal rather than
		// an empty pipe it has to guess about.
		_ = json.NewEncoder(os.Stdout).Encode(action.Response{OK: false, Error: err.Error()})
		os.Exit(1)
	}
	// gw-web.service runs with ProtectSystem=strict and a sudo'd child inherits
	// that mount namespace, so this helper would be root and still see a
	// read-only /opt and /etc.
	if err := action.EscapeServiceSandbox(append([]string{"web-action"}, args...)); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(action.Response{OK: false, Error: err.Error()})
		os.Exit(1)
	}

	paths, err := cli.Resolve()
	if err != nil {
		return err
	}
	h := action.Handler{
		Repo:     paths.Repo,
		Config:   paths.Config,
		AuthFile: webauth.AuthFile,
		Root:     "/",
		Systemd:  system.Systemd{},
	}
	return h.Run(os.Stdin, os.Stdout)
}

// minPasswordLen is the shortest password accepted. The dashboard can schedule
// a root job, so this password is a root password.
const minPasswordLen = 10

func cmdWebPasswd(args []string) error {
	cli.NeedRoot("web-passwd")

	existing := webauth.LoadPassword(webauth.AuthFile) != nil
	state := "first time"
	if existing {
		state = "replacing the current one"
	}
	fmt.Printf("Setting the dashboard password (%s).\n", state)
	fmt.Printf("Minimum %d characters. It is stored scrypt-hashed, never in the repo.\n\n", minPasswordLen)
	cli.Warn("The dashboard can schedule a job that runs as root, so this is a root password.")

	first, err := readPassword("New password: ")
	if err != nil {
		return err
	}
	second, err := readPassword("Repeat: ")
	if err != nil {
		return err
	}
	if first != second {
		return fmt.Errorf("passwords do not match")
	}
	if len(first) < minPasswordLen {
		return fmt.Errorf("too short — use at least %d characters", minPasswordLen)
	}

	if err := webauth.SavePassword(webauth.AuthFile, first); err != nil {
		return err
	}
	if err := os.Chown(webauth.AuthFile, 0, 0); err != nil {
		cli.Warn("could not set the owner on %s: %v", webauth.AuthFile, err)
	}
	fmt.Printf("\nsaved to %s (0600 root:root)\n", webauth.AuthFile)
	fmt.Println("Existing dashboard sessions stay valid until they expire;")
	fmt.Println("run 'systemctl restart gw-web' to sign everyone out now.")
	return nil
}

// readPassword reads without echoing. Falls back to a plain read when stdin is
// not a terminal, so the command still works from a script — but says so,
// because the password is then visible in the terminal's scrollback.
func readPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	if !term.IsTerminal(int(syscall.Stdin)) {
		var line string
		if _, err := fmt.Scanln(&line); err != nil {
			return "", err
		}
		cli.Warn("stdin is not a terminal, so the password was echoed")
		return line, nil
	}
	raw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
