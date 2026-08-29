package action

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// auth_status must report a password that gw web-passwd actually wrote. This is
// the call the login page makes, and getting it wrong tells the owner to run a
// command that cannot help them.
func TestAuthStatusSeesAPasswordWrittenByWebPasswd(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "web-auth.json")
	h := Handler{Repo: dir, Config: filepath.Join(dir, "gateway.toml"), AuthFile: authFile, Root: dir}

	if resp := h.Handle(Request{Action: "auth_status"}); resp.Data["password_set"] != false {
		t.Fatalf("a box with no password reported %v", resp.Data["password_set"])
	}

	// Exactly what `gw web-passwd` does.
	if err := SetPassword(authFile, "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	resp := h.Handle(Request{Action: "auth_status"})
	if !resp.OK || resp.Data["password_set"] != true {
		t.Fatalf("after web-passwd, auth_status still says %v", resp.Data)
	}
	if v := h.Handle(Request{Action: "verify_password", Password: "hunter2hunter2"}); v.Data["valid"] != true {
		t.Errorf("the password written by web-passwd does not verify: %v", v.Data)
	}

	raw, _ := os.ReadFile(authFile)
	if !strings.Contains(string(raw), "salt") {
		t.Errorf("the stored record looks wrong: %s", raw)
	}
}
