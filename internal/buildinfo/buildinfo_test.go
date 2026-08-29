package buildinfo

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// An explicit -ldflags stamp names a release, and must win over the commit.
func TestOverrideWins(t *testing.T) {
	if got := Resolve("v1.2.3", "").Version; got != "v1.2.3" {
		t.Errorf("version is %q, want the override", got)
	}
}

// The default "dev" placeholder is not an override — it is the absence of one,
// and treating it as a version is exactly how a binary ends up reporting "dev"
// forever.
func TestDevPlaceholderIsNotAVersion(t *testing.T) {
	got := Resolve("dev", "").Version
	if got == "dev" {
		t.Error(`"dev" was taken as a version instead of falling back to the commit`)
	}
	if got == "" {
		t.Error("no version was resolved at all")
	}
}

// Built inside a git work tree, Go records the commit with no build flags at
// all. This is what makes the version impossible to forget to stamp.
func TestResolvesTheCommitFromBuildInfo(t *testing.T) {
	info := Resolve("dev", "")
	if info.Version == "unknown" {
		t.Skip("built outside a git work tree")
	}
	// A short SHA, optionally marked dirty.
	base := info.Version
	if len(base) > 7 && base[7:] == "-dirty" {
		base = base[:7]
	}
	if len(base) != 7 {
		t.Errorf("version %q is not a short commit", info.Version)
	}
	for _, c := range base {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("version %q is not hexadecimal", info.Version)
			break
		}
	}
}

// The check that matters: bin/gw is a build artefact, so a pull updates the
// checkout and leaves the binary alone. Every fix you pull then appears to have
// done nothing.
func TestStaleDetectionFlagsANewerSourceFile(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A source file from the future stands in for one that arrived in a pull
	// after this binary was built.
	source := filepath.Join(repo, "internal", "config.go")
	if err := os.WriteFile(source, []byte("package config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	if err := os.Chtimes(source, future, future); err != nil {
		t.Fatal(err)
	}

	info := Resolve("dev", repo)
	if !info.Stale {
		t.Fatal("a source file newer than the binary was not reported as stale")
	}
	if info.StaleReason != filepath.Join("internal", "config.go") {
		t.Errorf("stale reason is %q, want the offending path", info.StaleReason)
	}
	if warning := info.StaleWarning(); warning == "" {
		t.Error("no warning text was produced")
	} else if !contains(warning, "go build") {
		t.Errorf("the warning does not say how to fix it: %q", warning)
	}
}

// A checkout that has not changed since the build must stay quiet. A warning
// that fires every time is one nobody reads.
func TestStaleDetectionIsQuietWhenUpToDate(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, "internal"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(repo, "internal", "config.go")
	if err := os.WriteFile(source, []byte("package config\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Older than the test binary, which was compiled moments ago.
	past := time.Now().Add(-24 * time.Hour)
	if err := os.Chtimes(source, past, past); err != nil {
		t.Fatal(err)
	}

	if info := Resolve("dev", repo); info.Stale {
		t.Errorf("an up-to-date checkout was reported stale (%s)", info.StaleReason)
	}
}

// The embedded assets change what the binary contains, so they count as source.
func TestEmbeddedAssetsCountAsSource(t *testing.T) {
	for _, dir := range []string{"templates", "dashboard/dist"} {
		repo := t.TempDir()
		path := filepath.Join(repo, filepath.FromSlash(dir), "asset")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		future := time.Now().Add(2 * time.Hour)
		if err := os.Chtimes(path, future, future); err != nil {
			t.Fatal(err)
		}
		if info := Resolve("dev", repo); !info.Stale {
			t.Errorf("a newer file in %s was not treated as source", dir)
		}
	}
}

// A repo that is not there, or is unreadable, must not break the command.
func TestMissingRepoIsNotAnError(t *testing.T) {
	if info := Resolve("dev", filepath.Join(t.TempDir(), "nope")); info.Stale {
		t.Error("a non-existent repo was reported stale")
	}
	if info := Resolve("dev", ""); info.Stale {
		t.Error("an empty repo path was reported stale")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
