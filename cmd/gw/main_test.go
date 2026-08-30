package main

import (
	"flag"
	"io"
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

// Flags and positional arguments must work in any order, and a flag's value
// must stay attached to it. Reordering arguments to achieve the first breaks
// the second — `--config path --check` became "the config `--check` is
// missing", which is a confusing way to learn about an argument parser.
func TestParseFlagsHandlesInterspersedArguments(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		wantConfig string
		wantCheck  bool
		wantRest   []string
	}{
		{"flags first", []string{"--config", "/tmp/a.toml", "--check"}, "/tmp/a.toml", true, nil},
		{"flag after positional", []string{"48", "--check"}, "", true, []string{"48"}},
		{"positional between flags", []string{"--check", "48", "--config", "/tmp/a.toml"},
			"/tmp/a.toml", true, []string{"48"}},
		{"equals form", []string{"--config=/tmp/a.toml", "1.2.3.4"}, "/tmp/a.toml", false, []string{"1.2.3.4"}},
		{"only positional", []string{"192.168.1.5"}, "", false, []string{"192.168.1.5"}},
		{"nothing", nil, "", false, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := flag.NewFlagSet("t", flag.ContinueOnError)
			fs.SetOutput(io.Discard)
			config := fs.String("config", "", "")
			check := fs.Bool("check", false, "")

			rest, err := parseFlags(fs, tc.args)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if *config != tc.wantConfig {
				t.Errorf("config is %q, want %q", *config, tc.wantConfig)
			}
			if *check != tc.wantCheck {
				t.Errorf("check is %v, want %v", *check, tc.wantCheck)
			}
			if len(rest) != len(tc.wantRest) {
				t.Fatalf("positional args are %v, want %v", rest, tc.wantRest)
			}
			for i := range rest {
				if rest[i] != tc.wantRest[i] {
					t.Errorf("positional args are %v, want %v", rest, tc.wantRest)
					break
				}
			}
		})
	}
}
