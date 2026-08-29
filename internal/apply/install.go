package apply

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/am1nr/gateway/internal/render"
)

// Install writes the rendered tree onto the filesystem.
//
// Modes come from the renderer, not from the umask: job scripts are 0700
// because they run as root and may hold credentials, and the sudoers fragment
// is 0440 because sudo refuses to read anything looser. Getting either wrong is
// silent — the job still runs, sudo just stops working.
func Install(files []render.File, opt Options) ([]string, error) {
	var written []string
	for _, f := range files {
		if !f.Installed() {
			continue
		}
		path := filepath.Join(opt.root(), f.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return written, fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
		}
		if err := writeFileAtomic(path, []byte(f.Content), f.Mode); err != nil {
			return written, fmt.Errorf("installing %s: %w", path, err)
		}
		written = append(written, f.Path)
	}
	return written, nil
}

// writeFileAtomic writes via a temporary file in the same directory and
// renames.
//
// A half-written nftables ruleset or Xray config is worse than an old one: the
// service that reads it next fails to start, and on a box being repaired
// remotely that is the difference between a config error and a drive back to
// the house. rename(2) within a directory is atomic, so a reader sees either
// the old file or the new one.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".gw-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	// fsync before rename: without it a power cut right after apply can leave
	// the rename durable and the contents not, which is an empty ruleset at
	// next boot.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Chmod explicitly: CreateTemp makes the file 0600 and the umask would
	// otherwise have the last word.
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// RemoveStale deletes units that stopped being rendered.
//
// A unit that is no longer generated has to stop being installed, or turning
// the scheduled updater off leaves it enabled and firing on the old schedule:
// the setting looks like it worked and changes nothing.
func RemoveStale(plan *Plan, opt Options) error {
	for _, unit := range plan.Stale {
		if err := os.Remove(filepath.Join(opt.root(), unit)); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing %s: %w", unit, err)
		}
	}
	return nil
}
