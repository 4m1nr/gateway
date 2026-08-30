package system

import (
	"os"
	"strings"
)

// TunnelStateFile is where the health watchdog records what it last saw.
// A variable rather than a constant so tests can point it elsewhere.
var TunnelStateFile = "/run/gateway/tunnel"

// BootstrapProxy decides whether to route a download through the bootstrap
// proxy.
//
// The proxy exists for one situation: fetching Xray, geodata or packages BEFORE
// the tunnel can carry them. Once the tunnel is up the box's own traffic is
// already routed through Xray by the OUTPUT chain, so sending it through the
// proxy as well means going out through a tunnel that is already carrying it —
// wasteful at best, and on a box whose proxy has since been shut down, a
// download that fails for no visible reason.
//
// An explicit override always wins. Someone passing --proxy has said what they
// want, and inferring around that would be worse than obeying it.
func BootstrapProxy(configured, override string) string {
	if override != "" {
		return override
	}
	if configured == "" {
		return ""
	}
	if TunnelIsUp() {
		return ""
	}
	return configured
}

// TunnelIsUp reports whether the watchdog last saw a working tunnel.
//
// Anything other than a recorded "up" — down, degraded, or never run — is
// treated as not up, so the proxy is used when in doubt. That is the safe
// direction: the cost of using it unnecessarily is a slower download, and the
// cost of skipping it when it was needed is a failed one.
func TunnelIsUp() bool {
	raw, err := os.ReadFile(TunnelStateFile)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == "up"
}
