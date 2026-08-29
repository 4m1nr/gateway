package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nft, sysctl, ip, visudo and useradd live in /usr/sbin, which is absent from
// some root PATHs. Calling them by bare name then fails in a way that looks
// like something else: `gw status` once reported "firewall not loaded" purely
// because it could not find nft.
func TestEnsurePathAddsSbin(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	ensurePath()

	dirs := map[string]bool{}
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		dirs[d] = true
	}
	for _, want := range []string{"/usr/sbin", "/sbin", "/usr/local/sbin", "/usr/local/bin"} {
		if !dirs[want] {
			t.Errorf("%s is not on PATH after ensurePath: %s", want, os.Getenv("PATH"))
		}
	}
	// The caller's own PATH must survive.
	if !dirs["/usr/bin"] {
		t.Error("ensurePath dropped an entry the caller had set")
	}
}

// A PATH that already has everything must be left exactly as it was: reordering
// it could shadow a tool the operator deliberately put first.
func TestEnsurePathLeavesACompletePathAlone(t *testing.T) {
	full := "/opt/mine/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	t.Setenv("PATH", full)
	ensurePath()
	if got := os.Getenv("PATH"); got != full {
		t.Errorf("PATH was rewritten:\n got %s\nwant %s", got, full)
	}
}

func TestEnsurePathHandlesAnEmptyPath(t *testing.T) {
	t.Setenv("PATH", "")
	ensurePath()
	got := os.Getenv("PATH")
	if !strings.Contains(got, "/usr/sbin") {
		t.Errorf("PATH is %q, want the sbin directories", got)
	}
	// No empty entry, which the shell reads as the current directory.
	for _, d := range filepath.SplitList(got) {
		if d == "" {
			t.Errorf("PATH contains an empty entry, which means the cwd: %q", got)
		}
	}
}
