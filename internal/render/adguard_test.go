package render

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/am1nr/gateway/internal/adguard"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/jsonx"
)

// decodeObject renders the overrides the way apply does — through JSON — so
// these tests see the same shape the YAML merge is handed.
func decodeObject(t *testing.T, o *jsonx.Object) map[string]any {
	t.Helper()
	raw, err := jsonx.EncodeIndented(o)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// clientEntry finds a rendered persistent client by name.
func clientEntry(t *testing.T, c *config.Config, name string) map[string]any {
	t.Helper()
	out := decodeObject(t, AdGuardOverrides(c))
	clients, ok := out["clients"].(map[string]any)
	if !ok {
		t.Fatalf("no clients block in the overrides")
	}
	list, ok := clients["persistent"].([]any)
	if !ok {
		t.Fatalf("clients.persistent is not a list")
	}
	for _, e := range list {
		entry, ok := e.(map[string]any)
		if ok && entry["name"] == name {
			return entry
		}
	}
	t.Fatalf("no persistent client named %q; AdGuard would not show it", name)
	return nil
}

// Every [[client]] the gateway enforces has to reach AdGuard, or the query log
// shows a bare address for a device the dashboard lists by name.
func TestAdGuardListsEveryClient(t *testing.T) {
	cfg := loadFixture(t, "default")
	if len(cfg.Clients) == 0 {
		t.Fatal("the default fixture has no clients to check")
	}
	for _, cl := range cfg.Clients {
		entry := clientEntry(t, cfg, cl.Name)
		ids, _ := entry["ids"].([]any)
		if len(ids) != 1 || ids[0] != cl.IP {
			t.Errorf("client %q has ids %v, want [%s]", cl.Name, ids, cl.IP)
		}
	}
}

// AdGuard consults a client's own filtering settings only when that client is
// not using the global ones, so the opt-out needs both keys. With
// use_global_settings left true, filtering_enabled is read by nothing and a
// direct device is filtered anyway.
func TestDirectClientOptsOutOfGlobalSettings(t *testing.T) {
	cfg := loadFixture(t, "default")
	for _, cl := range cfg.Clients {
		entry := clientEntry(t, cfg, cl.Name)
		wantFiltered := cl.Policy != "direct"
		if got := entry["filtering_enabled"]; got != wantFiltered {
			t.Errorf("%s (%s): filtering_enabled is %v, want %v",
				cl.Name, cl.Policy, got, wantFiltered)
		}
		if got := entry["use_global_settings"]; got != wantFiltered {
			t.Errorf("%s (%s): use_global_settings is %v, want %v — AdGuard "+
				"ignores filtering_enabled unless this is false",
				cl.Name, cl.Policy, got, wantFiltered)
		}
	}
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// AdGuard requires a uid and invents one for any client that arrives without
// it. Since the merge replaces the whole list, an invented uid means a new
// identity on every restart.
func TestClientUIDIsStableAndDistinct(t *testing.T) {
	cfg := loadFixture(t, "default")

	seen := map[string]string{}
	for _, cl := range cfg.Clients {
		uid, _ := clientEntry(t, cfg, cl.Name)["uid"].(string)
		if !uuidRE.MatchString(uid) {
			t.Errorf("%s: uid %q is not a UUID; AdGuard cannot parse it", cl.Name, uid)
		}
		if other, dup := seen[uid]; dup {
			t.Errorf("%s and %s share uid %s; AdGuard rejects the second one",
				other, cl.Name, uid)
		}
		seen[uid] = cl.Name

		if again := adguard.ClientUID(cl.IP); again != uid {
			t.Errorf("%s: uid is not stable (%s then %s)", cl.Name, uid, again)
		}
	}
}
