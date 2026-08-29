// Package cli holds the shared plumbing for the gw command: where the repo is,
// where the config is, and how output is coloured.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Paths locates everything gw reads and writes.
type Paths struct {
	// Repo is the checkout root.
	Repo string
	// Config is gateway.toml.
	Config string
	// Build is the staging tree.
	Build string
}

// EnvFile is the settings file `gw apply` renders. It records REPO, which is
// how a binary living outside the checkout finds it.
var EnvFile = "/usr/local/lib/gateway/env"

// Resolve works out where the repo is.
//
// Three sources, in order of how much they are trusted:
//
//  1. GW_REPO, for anything unusual.
//  2. The executable's own location. The documented install symlinks
//     /usr/local/bin/gw into the checkout, so the path is the symlink and not
//     its target — without resolving it the root lands in /usr/local and every
//     lookup misses.
//  3. The REPO value in the rendered env file.
//
// The third exists for the privileged helper. It is a COPY of this binary at
// /usr/local/lib/gateway/gw-action, deliberately outside the repo so the web
// process cannot rewrite what it sudoes — which means walking up from it gives
// /usr/local/lib, and every config read then fails with a path nobody
// recognises. The env file is what apply already writes down for exactly this
// question.
func Resolve() (Paths, error) {
	repo := os.Getenv("GW_REPO")

	if repo == "" {
		exe, err := os.Executable()
		if err != nil {
			return Paths{}, fmt.Errorf("locating the gw binary: %w", err)
		}
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			exe = resolved
		}
		// bin/gw -> repo root
		derived := filepath.Dir(filepath.Dir(exe))
		if isCheckout(derived) {
			repo = derived
		} else if recorded := recordedRepo(); recorded != "" {
			repo = recorded
		} else {
			// Neither worked. Keep the derived answer so the error names a real
			// path rather than an empty one.
			repo = derived
		}
	}

	abs, err := filepath.Abs(repo)
	if err != nil {
		return Paths{}, err
	}

	config := os.Getenv("GW_CONFIG")
	if config == "" {
		config = filepath.Join(abs, "gateway.toml")
	}
	return Paths{Repo: abs, Config: config, Build: filepath.Join(abs, "build")}, nil
}

// isCheckout reports whether a directory looks like the gateway repo.
//
// gateway.toml alone is not enough: it is gitignored, so a fresh clone does not
// have one yet and `gw init` has to be able to run there. cmd/gw is present in
// every checkout and in no install directory.
func isCheckout(dir string) bool {
	if dir == "" || dir == "/" {
		return false
	}
	for _, marker := range []string{"cmd/gw", "gateway.toml"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(marker))); err == nil {
			return true
		}
	}
	return false
}

// recordedRepo reads REPO out of the rendered env file.
func recordedRepo() string {
	repo := Env(EnvFile)["REPO"]
	if repo == "" || !isCheckout(repo) {
		return ""
	}
	return repo
}

// ---------------------------------------------------------------- output ---

// Colours are disabled when stdout is not a terminal or NO_COLOR is set, so
// piping `gw diff` into a file or a pager gives clean text.
var colour = shouldColour()

func shouldColour() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	st, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// SetColour forces colour on or off, for tests and for --no-color.
func SetColour(on bool) { colour = on }

const (
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	dim    = "\033[2m"
	off    = "\033[0m"
)

func paint(code, text string) string {
	if !colour {
		return text
	}
	return code + text + off
}

// Info reports normal progress.
func Info(format string, a ...any) {
	fmt.Printf("%s %s\n", paint(green, "==>"), fmt.Sprintf(format, a...))
}

// Warn reports something the reader should know but that is not fatal.
func Warn(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", paint(yellow, "[!]"), fmt.Sprintf(format, a...))
}

// Errorf reports a failure.
func Errorf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s %s\n", paint(red, "[x]"), fmt.Sprintf(format, a...))
}

// Dim prints secondary detail.
func Dim(format string, a ...any) {
	fmt.Println(paint(dim, fmt.Sprintf(format, a...)))
}

// Green, Red, Yellow colour a fragment for inline use.
func Green(s string) string  { return paint(green, s) }
func Red(s string) string    { return paint(red, s) }
func Yellow(s string) string { return paint(yellow, s) }
func Dimmed(s string) string { return paint(dim, s) }

// NeedRoot exits unless running as root.
func NeedRoot(command string) {
	if os.Geteuid() != 0 {
		Errorf("%s needs root (try: sudo gw %s)", command, command)
		os.Exit(1)
	}
}

// Die reports and exits.
func Die(format string, a ...any) {
	Errorf(format, a...)
	os.Exit(1)
}

// Env reads the rendered env file that the helper scripts source.
//
// Sourced values are shell-quoted, so this strips one layer of quoting rather
// than grepping raw text.
func Env(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"`)
	}
	return out
}
