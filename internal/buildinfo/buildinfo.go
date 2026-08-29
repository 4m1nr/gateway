// Package buildinfo answers "which code is actually running?".
//
// That question matters more here than in most projects. bin/gw is a build
// artefact, so a `git pull` updates the checkout and leaves the binary alone —
// every fix you pull then appears to have done nothing, and the only evidence
// is that the output never changes. The old shell CLI had the same hazard in a
// different shape (a copy at /usr/local/bin surviving pulls) and warned about
// it; this is the version of that warning that fits a compiled binary.
package buildinfo

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"
)

// Info describes the running binary.
type Info struct {
	// Version is the commit it was built from, with -dirty when the tree had
	// uncommitted changes. "unknown" when it was built outside a git work tree.
	Version string
	// CommittedAt is the timestamp of the commit it was built from. Go records
	// the commit's time, not the compile time — labelling it "built" would be a
	// small lie on the one line whose whole job is to be trusted.
	CommittedAt time.Time
	// Stale reports that a source file in the repo is newer than the binary —
	// you pulled, or edited, and did not rebuild.
	Stale bool
	// StaleReason names the newest file that is ahead of the binary.
	StaleReason string
	// Repo is the checkout the binary was resolved against, if any.
	Repo string
}

// Resolve reports what is running.
//
// override is the -ldflags stamp, used when it is set to something other than
// the "dev" default: a release build can name a tag rather than a commit. Every
// other build gets its identity from the VCS information Go records
// automatically, which needs no build flags and cannot be forgotten.
func Resolve(override, repo string) Info {
	info := Info{Version: "unknown", Repo: repo}

	if override != "" && override != "dev" {
		info.Version = override
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		var revision, modified string
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value
			case "vcs.time":
				if t, err := time.Parse(time.RFC3339, s.Value); err == nil {
					info.CommittedAt = t
				}
			}
		}
		if info.Version == "unknown" && revision != "" {
			short := revision
			if len(short) > 7 {
				short = short[:7]
			}
			info.Version = short
			if modified == "true" {
				// Worth saying: a binary built from a dirty tree does not
				// correspond to any commit, so its version cannot be looked up.
				info.Version += "-dirty"
			}
		}
	}

	if repo != "" {
		info.Stale, info.StaleReason = checkStale(repo)
	}
	return info
}

// sourceDirs are walked to decide whether the binary is behind the checkout.
// Only what the binary is compiled from: the dashboard's built assets and the
// templates are embedded, so they count too.
var sourceDirs = []string{"cmd", "internal", "templates", "dashboard/dist", "vendor"}

// sourceFiles are individual files that also change what a build produces.
var sourceFiles = []string{"go.mod", "go.sum", "embed.go"}

// checkStale reports whether any source file is newer than the running binary.
//
// Modification time rather than the commit timestamp: a commit made last week
// and pulled today is new to this box, and its commit time would say otherwise.
// What matters is when the file arrived, which is exactly what mtime records.
func checkStale(repo string) (bool, string) {
	exe, err := os.Executable()
	if err != nil {
		return false, ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	exeInfo, err := os.Stat(exe)
	if err != nil {
		return false, ""
	}
	built := exeInfo.ModTime()

	var newest time.Time
	var newestPath string
	consider := func(path string, mod time.Time) {
		if mod.After(newest) {
			newest, newestPath = mod, path
		}
	}

	for _, dir := range sourceDirs {
		full := filepath.Join(repo, dir)
		_ = filepath.WalkDir(full, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				// A missing directory is not an error worth reporting: a
				// deployment may not carry every one of them.
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if fi, err := d.Info(); err == nil {
				consider(path, fi.ModTime())
			}
			return nil
		})
	}
	for _, name := range sourceFiles {
		if fi, err := os.Stat(filepath.Join(repo, name)); err == nil {
			consider(filepath.Join(repo, name), fi.ModTime())
		}
	}

	if newestPath == "" || !newest.After(built) {
		return false, ""
	}
	rel, err := filepath.Rel(repo, newestPath)
	if err != nil {
		rel = newestPath
	}
	return true, rel
}

// StaleWarning is the advice to print when the binary is behind the checkout.
func (i Info) StaleWarning() string {
	if !i.Stale {
		return ""
	}
	return fmt.Sprintf("%s is newer than the running binary — you are not running "+
		"the code in this checkout.\nRebuild: cd %s && GOTOOLCHAIN=local CGO_ENABLED=0 "+
		"go build -mod=vendor -trimpath -o bin/gw ./cmd/gw", i.StaleReason, i.Repo)
}

// String renders the version line.
func (i Info) String() string {
	if i.CommittedAt.IsZero() {
		return i.Version
	}
	return fmt.Sprintf("%s  (%s)", i.Version, i.CommittedAt.Local().Format("2006-01-02"))
}

// Short is just the identity, for `gw version`.
func (i Info) Short() string { return i.Version }
