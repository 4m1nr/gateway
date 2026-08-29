package action

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/config"
)

// A change that would leave the config invalid must not reach the file. The
// dashboard can otherwise save a gateway that will not start, and the next
// thing anyone learns is that `gw apply` fails.
func TestInvalidChangeIsNeverSaved(t *testing.T) {
	h := newHandler(t)
	before, err := os.ReadFile(h.Config)
	if err != nil {
		t.Fatal(err)
	}

	resp := h.Handle(Request{
		Action: "config_write", Section: "net",
		// A static_ip outside the LAN: parses fine, and produces a box that
		// cannot reach its own router.
		JSON: `{"wan_if":"eth0","lan_cidr":"192.168.1.0/24","router":"192.168.1.1","static_ip":"10.0.0.5"}`,
	})
	if resp.OK {
		t.Fatal("a change that invalidates the config was saved")
	}
	if !strings.Contains(resp.Error, "not saved") {
		t.Errorf("the error does not say the change was refused: %q", resp.Error)
	}

	after, err := os.ReadFile(h.Config)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Error("the config file changed despite the refusal")
	}
}

// A valid change is saved, still loads, and keeps everything else intact.
func TestValidChangeIsSavedAndKeepsTheRest(t *testing.T) {
	h := newHandler(t)

	resp := h.Handle(Request{
		Action: "config_write", Section: "dns",
		JSON: `{"upstreams_direct":["9.9.9.9"],"direct_suffixes":["ir","local"],"intercept":true,"adguard_port":53}`,
	})
	if !resp.OK {
		t.Fatalf("a valid change was refused: %s", resp.Error)
	}
	if !resp.PendingApply {
		t.Error("the change was saved but not marked as needing apply")
	}

	cfg, err := config.Load(h.Config)
	if err != nil {
		t.Fatalf("the saved config does not load: %v", err)
	}
	if len(cfg.UpDirect) != 1 || cfg.UpDirect[0] != "9.9.9.9" {
		t.Errorf("the new resolver was not saved: %v", cfg.UpDirect)
	}
	// The profile defined in the base config must survive an unrelated edit.
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Name != "work" {
		t.Errorf("an unrelated section was lost: %v", cfg.ProfileNames())
	}
}

// Ports arrive from JSON as float64. Writing 53.0 produces a config that does
// not load, or one that does and means something else.
func TestNumbersSurviveTheJSONRoundTrip(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{
		Action: "config_write", Section: "dns",
		JSON: `{"adguard_port":5353,"adguard_ui_port":3000,"querylog_days":3}`,
	})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	raw, _ := os.ReadFile(h.Config)
	if strings.Contains(string(raw), "5353.0") || strings.Contains(string(raw), "5353e") {
		t.Errorf("a port was written as a float:\n%s", raw)
	}
	cfg, err := config.Load(h.Config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DNSPort != 5353 {
		t.Errorf("port is %d, want 5353", cfg.DNSPort)
	}
}

// Profiles and their routes go through the same path as everything else.
func TestProfilesCanBeWritten(t *testing.T) {
	h := newHandler(t)
	body := `[
	  {"name":"work-laptop","base":"proxy","route":[
	    {"via":"direct","domains":["domain:corp.example"],"ips":["10.20.0.0/16"]}
	  ]}
	]`
	resp := h.Handle(Request{Action: "config_write", Section: "profile", JSON: body})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	cfg, err := config.Load(h.Config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 1 || cfg.Profiles[0].Name != "work-laptop" {
		t.Fatalf("profiles are %v", cfg.ProfileNames())
	}
	p := cfg.Profiles[0]
	if len(p.Routes) != 1 || p.Routes[0].Via != "direct" {
		t.Errorf("the profile's route was not saved: %+v", p.Routes)
	}
	if len(p.Routes[0].IPs) != 1 || p.Routes[0].IPs[0] != "10.20.0.0/16" {
		t.Errorf("the route's networks were lost: %+v", p.Routes[0])
	}
}

// A profile whose rule points at an upstream that does not exist must be
// refused: it parses, and it silently routes nothing.
func TestProfileWithAnUnknownTargetIsRefused(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{Action: "config_write", Section: "profile",
		JSON: `[{"name":"p","base":"proxy","route":[{"via":"ghost","domains":["a.example"]}]}]`})
	if resp.OK {
		t.Fatal("a profile routing to an unknown target was saved")
	}
	if !strings.Contains(resp.Error, "not a known target") {
		t.Errorf("the error does not explain: %q", resp.Error)
	}
}

// This runs as root. Replacing an arbitrary named section would include ones
// whose meaning the UI does not model.
func TestOnlyWhitelistedSectionsCanBeWritten(t *testing.T) {
	h := newHandler(t)
	for _, section := range []string{"", "unknown", "../etc/passwd", "xray.outbound"} {
		if resp := h.Handle(Request{Action: "config_write", Section: section, JSON: "{}"}); resp.OK {
			t.Errorf("section %q was accepted", section)
		}
	}
}

// Reading must work even when the config does not load — that is exactly when
// someone needs to see it.
func TestConfigReadWorksOnABrokenConfig(t *testing.T) {
	h := newHandler(t)
	// Break it in a way that still parses as TOML.
	raw, _ := os.ReadFile(h.Config)
	broken := strings.Replace(string(raw), `static_ip = "192.168.1.2"`, `static_ip = "10.0.0.5"`, 1)
	if err := os.WriteFile(h.Config, []byte(broken), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := h.Handle(Request{Action: "config_read"})
	if !resp.OK {
		t.Fatalf("reading a broken config failed outright: %s", resp.Error)
	}
	if msg, _ := resp.Data["config_error"].(string); msg == "" {
		t.Error("a config that does not load reported no error")
	}
	if _, ok := resp.Data["config"]; !ok {
		t.Error("the config itself was not returned, so it cannot be repaired from here")
	}
}

// A whole-file rewrite is the one operation where yesterday's config matters.
func TestSaveKeepsABackup(t *testing.T) {
	h := newHandler(t)
	original, _ := os.ReadFile(h.Config)

	resp := h.Handle(Request{Action: "config_write", Section: "dns", JSON: `{"querylog_days":7}`})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	backup, err := os.ReadFile(h.Config + ".bak")
	if err != nil {
		t.Fatalf("no backup was written: %v", err)
	}
	if string(backup) != string(original) {
		t.Error("the backup is not the file that was replaced")
	}

	restored := h.Handle(Request{Action: "config_backup"})
	if !restored.OK {
		t.Fatalf("the backup could not be read back: %s", restored.Error)
	}
	if body, _ := restored.Data["toml"].(string); body != string(original) {
		t.Error("config_backup returned something other than the previous file")
	}
}

// Deleting a section is how the UI removes every profile, or every custom route.
func TestNullRemovesASection(t *testing.T) {
	h := newHandler(t)
	if resp := h.Handle(Request{Action: "config_write", Section: "profile", JSON: "null"}); !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	cfg, err := config.Load(h.Config)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Profiles) != 0 {
		t.Errorf("profiles survived deletion: %v", cfg.ProfileNames())
	}
}

// Malformed JSON is a client bug; it must not reach the file.
func TestMalformedJSONIsRefused(t *testing.T) {
	h := newHandler(t)
	before, _ := os.ReadFile(h.Config)
	if resp := h.Handle(Request{Action: "config_write", Section: "dns", JSON: "{not json"}); resp.OK {
		t.Fatal("malformed JSON was accepted")
	}
	after, _ := os.ReadFile(h.Config)
	if string(before) != string(after) {
		t.Error("the config changed after a malformed write")
	}
}

func TestConfigReadReturnsUsableJSON(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{Action: "config_read"})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	raw, err := json.Marshal(resp.Data["config"])
	if err != nil {
		t.Fatalf("the config cannot be sent as JSON: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["net"]; !ok {
		t.Errorf("the returned config has no [net]: %s", raw)
	}
}
