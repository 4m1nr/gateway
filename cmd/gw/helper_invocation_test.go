package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The sudoers grant names /usr/local/lib/gateway/gw-action with NO arguments —
// that is the security property, and it means the helper can never be told
// which subcommand it is.
//
// It once printed usage and exited 0 without reading stdin. Every dashboard
// action failed, and because the login page folded that into "no password is
// set", the owner was told to run `gw web-passwd` — which could not possibly
// help. This builds the binary, installs it under the helper's name, and
// invokes it the way sudo does.
func TestHelperAnswersWhenInvokedWithNoArguments(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, actionHelperName)

	build := exec.Command("go", "build", "-mod=vendor", "-o", helper, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the helper: %v\n%s", err, out)
	}

	cmd := exec.Command(helper) // no arguments, exactly as sudoers permits
	cmd.Stdin = strings.NewReader(`{"action":"auth_status"}`)
	out, _ := cmd.CombinedOutput()

	if strings.Contains(string(out), "the only command you should need") {
		t.Fatalf("the helper printed usage instead of handling the request:\n%s", out)
	}

	// It must answer in JSON. Running as an unprivileged test user the correct
	// answer is a refusal — but a structured one the caller can read.
	var resp struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("the helper did not reply with JSON: %v\noutput: %s", err, out)
	}
	if os.Geteuid() != 0 && !strings.Contains(resp.Error, "must run as root") {
		t.Errorf("expected a root refusal, got: %+v", resp)
	}
}

// Invoked under any other name it is the ordinary CLI, and no arguments still
// means usage.
func TestUnderItsOwnNameNoArgumentsPrintsUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	dir := t.TempDir()
	gw := filepath.Join(dir, "gw")

	build := exec.Command("go", "build", "-mod=vendor", "-o", gw, ".")
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building: %v\n%s", err, out)
	}

	out, err := exec.Command(gw).CombinedOutput()
	if err != nil {
		t.Fatalf("gw with no arguments failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "the only command you should need") {
		t.Errorf("gw with no arguments did not print usage:\n%s", out)
	}
}

// The name in the sudoers template and the name the binary answers to have to
// be the same string. A rename in one place alone is silent: the grant points
// at a path nothing installs, or the helper never recognises itself.
func TestSudoersNamesTheHelperTheBinaryAnswersTo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "templates", "sudoers.gw-web"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "/"+actionHelperName+"\n") {
		t.Errorf("the sudoers template does not grant a path ending in %q:\n%s",
			actionHelperName, raw)
	}
	if !strings.HasSuffix(actionHelperPath, "/"+actionHelperName) {
		t.Errorf("apply installs the helper at %q, which does not end in %q",
			actionHelperPath, actionHelperName)
	}
	if !strings.Contains(string(raw), actionHelperPath) {
		t.Errorf("the sudoers grant does not name %q, the path apply installs to",
			actionHelperPath)
	}
}
