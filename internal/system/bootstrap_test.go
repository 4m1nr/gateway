package system

import (
	"os"
	"path/filepath"
	"testing"
)

// withTunnelState points the state file at a temp copy.
func withTunnelState(t *testing.T, state string) {
	t.Helper()
	old := TunnelStateFile
	t.Cleanup(func() { TunnelStateFile = old })

	if state == "" {
		TunnelStateFile = filepath.Join(t.TempDir(), "absent")
		return
	}
	path := filepath.Join(t.TempDir(), "tunnel")
	if err := os.WriteFile(path, []byte(state+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	TunnelStateFile = path
}

// The proxy exists for fetching things before the tunnel can carry them. Once
// it is up, using the proxy sends the download through a tunnel that is already
// carrying it.
func TestConfiguredProxyIsSkippedWhenTheTunnelIsUp(t *testing.T) {
	withTunnelState(t, "up")
	if got := BootstrapProxy("socks5h://127.0.0.1:1080", ""); got != "" {
		t.Errorf("proxy %q was used with the tunnel up", got)
	}
}

// Down, degraded, or never run: use it. Using it unnecessarily costs a slower
// download; skipping it when it was needed costs a failed one.
func TestConfiguredProxyIsUsedWhenTheTunnelIsNot(t *testing.T) {
	for _, state := range []string{"down", "degraded", "unknown", ""} {
		withTunnelState(t, state)
		if got := BootstrapProxy("socks5h://127.0.0.1:1080", ""); got == "" {
			t.Errorf("the proxy was skipped with the tunnel %q", orNone(state))
		}
	}
}

// Someone passing --proxy has said what they want.
func TestExplicitOverrideAlwaysWins(t *testing.T) {
	withTunnelState(t, "up")
	if got := BootstrapProxy("socks5h://127.0.0.1:1080", "http://override:3128"); got != "http://override:3128" {
		t.Errorf("an explicit override was ignored with the tunnel up: %q", got)
	}
	withTunnelState(t, "down")
	if got := BootstrapProxy("", "http://override:3128"); got != "http://override:3128" {
		t.Errorf("an explicit override was ignored with no configured proxy: %q", got)
	}
}

func TestNoProxyConfiguredMeansNoProxy(t *testing.T) {
	for _, state := range []string{"up", "down", ""} {
		withTunnelState(t, state)
		if got := BootstrapProxy("", ""); got != "" {
			t.Errorf("a proxy appeared from nowhere: %q", got)
		}
	}
}

func orNone(s string) string {
	if s == "" {
		return "(no state file)"
	}
	return s
}
