package action

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const baseConfig = `
[net]
wan_if    = "eth0"
lan_cidr  = "192.168.1.0/24"
router    = "192.168.1.1"
static_ip = "192.168.1.2"

[xray.outbound]
file = "main.json"

[[profile]]
name = "work"
[[profile.route]]
via     = "direct"
domains = ["domain:corp.example"]
`

const outboundJSON = `{
  "protocol": "vless",
  "settings": {"vnext": [{"address": "example.com", "port": 443,
    "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
  "streamSettings": {"network": "xhttp", "security": "tls"}
}`

func newHandler(t *testing.T) Handler {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.json"), []byte(outboundJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "gateway.toml")
	if err := os.WriteFile(cfg, []byte(baseConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	return Handler{
		Repo:     dir,
		Config:   cfg,
		AuthFile: filepath.Join(dir, "web-auth.json"),
		Root:     dir,
	}
}

func TestUnknownActionIsRefused(t *testing.T) {
	resp := newHandler(t).Handle(Request{Action: "rm -rf"})
	if resp.OK {
		t.Fatal("an unknown action was accepted")
	}
	if !strings.Contains(resp.Error, "unknown action") {
		t.Errorf("error is %q", resp.Error)
	}
}

// The web process must not be able to widen the set of policies it may assign.
// The list comes from the config, read here as root.
func TestPolicyCannotBeWidenedByTheRequest(t *testing.T) {
	h := newHandler(t)
	for _, policy := range []string{"nonsense", "", "root", "../proxy"} {
		resp := h.Handle(Request{
			Action: "client_add", IP: "192.168.1.50", Name: "nas", Policy: policy,
		})
		if resp.OK {
			t.Errorf("policy %q was accepted", policy)
		}
	}
	// A profile the config actually defines is accepted.
	if resp := h.Handle(Request{
		Action: "client_add", IP: "192.168.1.50", Name: "nas", Policy: "work",
	}); !resp.OK {
		t.Errorf("a valid profile policy was refused: %s", resp.Error)
	}
}

// An address outside the LAN, or the gateway itself, is refused here rather
// than trusted from the request.
func TestClientAddressIsRevalidatedAsRoot(t *testing.T) {
	h := newHandler(t)
	for _, tc := range []struct{ ip, why string }{
		{"8.8.8.8", "outside the LAN"},
		{"192.168.2.5", "outside the LAN"},
		{"192.168.1.1", "the router"},
		{"192.168.1.2", "the gateway itself"},
		{"not-an-ip", "not an address"},
		{"", "empty"},
	} {
		resp := h.Handle(Request{Action: "client_add", IP: tc.ip, Name: "x", Policy: "proxy"})
		if resp.OK {
			t.Errorf("%s (%s) was accepted", tc.ip, tc.why)
		}
	}
}

// The name is written into gateway.toml and rendered in a browser. A quote or a
// newline would close the TOML string and open a new table — config injection
// from the dashboard.
func TestClientNameIsConstrained(t *testing.T) {
	h := newHandler(t)
	for _, name := range []string{
		`evil"`,
		"line\nbreak",
		`x"` + "\npolicy = \"block",
		"<script>alert(1)</script>",
		strings.Repeat("a", 33),
		"",
	} {
		resp := h.Handle(Request{Action: "client_add", IP: "192.168.1.50", Name: name, Policy: "proxy"})
		if resp.OK {
			t.Errorf("name %q was accepted", name)
		}
	}
	if resp := h.Handle(Request{
		Action: "client_add", IP: "192.168.1.50", Name: "living room tv", Policy: "proxy",
	}); !resp.OK {
		t.Errorf("an ordinary name was refused: %s", resp.Error)
	}
}

// A malformed cron line in /etc/cron.d is silently ignored rather than
// rejected, so the job would never run and nothing would say why.
func TestJobScheduleIsRevalidatedAsRoot(t *testing.T) {
	h := newHandler(t)
	for _, schedule := range []string{"", "0 4 * *", "@fortnightly", "0 4 * * * *", "0 4 * * ;reboot"} {
		resp := h.Handle(Request{
			Action: "job_add", Name: "probe", Schedule: schedule, Script: "true\n",
		})
		if resp.OK {
			t.Errorf("schedule %q was accepted", schedule)
		}
	}
	if resp := h.Handle(Request{
		Action: "job_add", Name: "probe", Schedule: "*/5 * * * *", Script: "true\n",
	}); !resp.OK {
		t.Errorf("a valid schedule was refused: %s", resp.Error)
	}
}

func TestJobNameAndUserAreConstrained(t *testing.T) {
	h := newHandler(t)
	for _, name := range []string{"Probe", "probe!", "../etc/passwd", "", strings.Repeat("a", 25)} {
		if resp := h.Handle(Request{
			Action: "job_add", Name: name, Schedule: "@daily", Script: "true\n",
		}); resp.OK {
			t.Errorf("job name %q was accepted", name)
		}
	}
	for _, user := range []string{"root; rm -rf /", "Root", "-x", "0"} {
		if resp := h.Handle(Request{
			Action: "job_add", Name: "probe", Schedule: "@daily", Script: "true\n", User: user,
		}); resp.OK {
			t.Errorf("user %q was accepted", user)
		}
	}
}

func TestJobScriptSizeIsBounded(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{
		Action: "job_add", Name: "big", Schedule: "@daily",
		Script: strings.Repeat("x", 65*1024),
	})
	if resp.OK {
		t.Error("an oversized script was accepted")
	}
}

// A change that saves but leaves the config unloadable must be reported, or the
// next apply — or the next boot — fails for a reason nobody connects to it.
func TestConfigIsCheckedAfterAnEdit(t *testing.T) {
	h := newHandler(t)
	if resp := h.Handle(Request{
		Action: "client_add", IP: "192.168.1.50", Name: "nas", Policy: "proxy",
	}); !resp.OK {
		t.Fatalf("setup failed: %s", resp.Error)
	}
	// Break the outbound the config depends on, then edit again.
	os.WriteFile(filepath.Join(h.Repo, "main.json"), []byte("{not json"), 0o600)
	resp := h.Handle(Request{Action: "client_add", IP: "192.168.1.51", Name: "tv", Policy: "proxy"})
	if resp.OK {
		t.Error("an edit that leaves the config unloadable was reported as success")
	}
}

// Only a named set of units may be restarted. "Restart any unit named by an
// HTTP request" is a much larger grant than it looks.
func TestOnlyWhitelistedUnitsCanBeRestarted(t *testing.T) {
	h := newHandler(t)
	for _, unit := range []string{
		"sshd.service", "systemd-logind.service", "", "xray.service; reboot",
		"../../../etc/passwd", "*",
	} {
		if resp := h.Handle(Request{Action: "restart_unit", Unit: unit}); resp.OK {
			t.Errorf("unit %q was accepted", unit)
		}
	}
}

// The password is verified here, as root, so the hash never reaches the
// network-facing process.
func TestPasswordVerificationHappensHere(t *testing.T) {
	h := newHandler(t)
	if resp := h.Handle(Request{Action: "auth_status"}); !resp.OK ||
		resp.Data["password_set"] != false {
		t.Fatalf("expected no password to be set, got %+v", resp)
	}

	// Write a record the way `gw web-passwd` does.
	if err := writeTestPassword(h.AuthFile, "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	resp := h.Handle(Request{Action: "verify_password", Password: "hunter2hunter2"})
	if !resp.OK || resp.Data["valid"] != true {
		t.Errorf("the correct password did not verify: %+v", resp)
	}
	resp = h.Handle(Request{Action: "verify_password", Password: "wrong"})
	if !resp.OK || resp.Data["valid"] != false {
		t.Errorf("a wrong password verified: %+v", resp)
	}
	// The response must never carry the hash or the salt.
	raw, _ := json.Marshal(resp)
	for _, leak := range []string{"salt", "hash"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the response leaks the %s: %s", leak, raw)
		}
	}
}

// Importing a link writes nothing: the result goes to the editor so it can be
// reviewed before it becomes the tunnel everything routes through.
func TestImportLinkWritesNothing(t *testing.T) {
	h := newHandler(t)
	before, _ := os.ReadFile(h.Config)
	resp := h.Handle(Request{
		Action: "import_link",
		Link:   "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=xhttp&security=tls&path=/x",
	})
	if !resp.OK {
		t.Fatalf("a valid link was refused: %s", resp.Error)
	}
	if s, _ := resp.Data["json"].(string); !strings.Contains(s, `"protocol": "vless"`) {
		t.Errorf("the imported outbound looks wrong: %v", resp.Data["json"])
	}
	after, _ := os.ReadFile(h.Config)
	if string(before) != string(after) {
		t.Error("importing a link modified the config")
	}
}

func TestImportLinkRejectsNonsense(t *testing.T) {
	h := newHandler(t)
	if resp := h.Handle(Request{Action: "import_link", Link: "file:///etc/passwd"}); resp.OK {
		t.Error("a non-share-link URL was accepted")
	}
}

// The generated config is what Xray will actually be handed, so the viewer must
// show the real thing rather than a re-render of the parts.
func TestGeneratedConfigIsTheRealOutput(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{Action: "generated_config"})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	body, _ := resp.Data["config"].(string)
	for _, want := range []string{`"inbounds"`, `"outbounds"`, `"routing"`, `"tproxy-in"`} {
		if !strings.Contains(body, want) {
			t.Errorf("the generated config has no %s", want)
		}
	}
	// The loop guard must be visible in what the viewer shows.
	if !strings.Contains(body, `"mark": 255`) {
		t.Error("the generated config does not carry the outbound mark")
	}
}

// Outbounds are surfaced with their JSON so the editor can show exactly what
// the gateway loaded, including the two fields it injects.
func TestOutboundsCarryTheInjectedFields(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{Action: "outbounds"})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	list, _ := resp.Data["outbounds"].([]map[string]any)
	if len(list) == 0 {
		t.Fatal("no outbounds were returned")
	}
	body, _ := list[0]["json"].(string)
	if !strings.Contains(body, `"tag": "proxy"`) {
		t.Error("the outbound does not show its assigned tag")
	}
	if !strings.Contains(body, `"mark": 255`) {
		t.Error("the outbound does not show the loop-guard mark")
	}
}

// The runner must not crash or hang on hostile input: it is the boundary, and
// the caller is assumed hostile.
func TestRunHandlesHostileInput(t *testing.T) {
	h := newHandler(t)
	for _, body := range []string{
		"", "not json", "[]", "null", `{"action":123}`,
		`{"action":"status"` + strings.Repeat(" ", 1000),
	} {
		var out strings.Builder
		if err := h.Run(strings.NewReader(body), &out); err != nil {
			t.Errorf("Run(%q) returned an error: %v", body, err)
		}
		var resp Response
		if err := json.Unmarshal([]byte(out.String()), &resp); err != nil {
			t.Errorf("Run(%q) did not produce a JSON response: %q", body, out.String())
		}
	}
}

func writeTestPassword(path, password string) error {
	// Uses the same code path `gw web-passwd` does.
	return SetPassword(path, password)
}
