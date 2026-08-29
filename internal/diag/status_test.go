package diag

import (
	"os"
	"path/filepath"
	"testing"
)

func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for path, content := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestCollectReadsWatchdogState(t *testing.T) {
	root := fakeRoot(t, map[string]string{
		"run/gateway/tunnel":   "degraded\n",
		"run/gateway/fails":    "4\n",
		"run/gateway/lifeline": "1\n",
		"run/gateway/detail":   "interception broken\n",
		"usr/local/lib/gateway/env": `DEFAULT_POLICY="proxy"
LAN_CIDR="192.168.1.0/24"
BOX_IP="192.168.1.2"
PROFILES="work-laptop,mostly-local"
`,
	})
	s := Collector{Root: root}.Collect()

	if s.Tunnel != Degraded {
		t.Errorf("tunnel is %q, want degraded", s.Tunnel)
	}
	if s.Fails != 4 {
		t.Errorf("fails is %d, want 4", s.Fails)
	}
	if !s.Lifeline {
		t.Error("lifeline should be engaged")
	}
	if s.Detail != "interception broken" {
		t.Errorf("detail is %q", s.Detail)
	}
	if s.LAN != "192.168.1.0/24" || s.BoxIP != "192.168.1.2" {
		t.Errorf("env values not read: %+v", s)
	}
	if len(s.Profiles) != 2 || s.Profiles[0] != "work-laptop" {
		t.Errorf("profiles are %v", s.Profiles)
	}
}

// A box where the watchdog has never run must report "unknown", not "up". A
// status that guesses optimistically is worse than one that admits it does not
// know.
func TestCollectDefaultsToUnknown(t *testing.T) {
	s := Collector{Root: fakeRoot(t, nil)}.Collect()
	if s.Tunnel != Unknown {
		t.Errorf("tunnel is %q on a box with no state, want unknown", s.Tunnel)
	}
	if s.DefaultPolicy != "proxy" {
		t.Errorf("default policy is %q, want the proxy fallback", s.DefaultPolicy)
	}
}

// nft wraps a long element list across lines and indents continuations with
// tabs. A single-line pattern reports an empty set, which reads as "no clients
// are intercepted" on a box where they are.
func TestSetElementsHandlesWrappedOutput(t *testing.T) {
	out := `table inet gateway {
	set proxy_clients {
		type ipv4_addr
		flags interval
		elements = { 192.168.1.50, 192.168.1.51,
			     192.168.1.52, 100.64.0.0/10 }
	}

	set direct_clients {
		type ipv4_addr
		flags interval
	}
}`
	got := setElements(out, "proxy_clients")
	want := []string{"192.168.1.50", "192.168.1.51", "192.168.1.52", "100.64.0.0/10"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("element %d is %q, want %q", i, got[i], want[i])
		}
	}
	// A set with no elements must come back empty, not nil, so JSON renders [].
	if empty := setElements(out, "direct_clients"); empty == nil || len(empty) != 0 {
		t.Errorf("an empty set gave %#v, want an empty slice", empty)
	}
}

// There are two killswitch rules — listed clients and the LAN catch-all — and
// reporting only one understates what the gateway actually refused.
func TestKillswitchDropsAreSummed(t *testing.T) {
	// Exercised through the parsing helpers, since nft is not run in tests.
	out := `		ip saddr @proxy_clients counter packets 120 bytes 9000 drop comment "killswitch"
		ip saddr $LAN counter packets 33 bytes 2000 drop comment "killswitch-default"`
	total := 0
	for _, line := range splitLines(out) {
		if m := packetsRE.FindStringSubmatch(line); m != nil && contains(line, "killswitch") {
			total += atoi(m[1])
		}
	}
	if total != 153 {
		t.Errorf("summed %d killswitch drops, want 153", total)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return out
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func TestSystemInfoIsPopulated(t *testing.T) {
	// Reads the real /proc, which every Linux box running this has.
	s := Collector{}.Collect()
	if s.System.Uptime <= 0 {
		t.Error("uptime was not read")
	}
	if s.System.MemTotal <= 0 {
		t.Error("memory total was not read")
	}
	if s.System.DiskTotal <= 0 {
		t.Error("disk total was not read")
	}
	if len(s.System.Load) != 3 {
		t.Errorf("load average has %d entries, want 3", len(s.System.Load))
	}
}
