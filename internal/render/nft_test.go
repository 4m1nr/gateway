package render

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The generated ruleset is fed to a real `nft -c`. Nothing else catches a
// semantic error — an overlapping interval, a match nft will not accept — and
// the consequence is gw-network failing to load at boot, which leaves the box
// forwarding with no firewall at all.
func TestNftAcceptsEveryRuleset(t *testing.T) {
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft is not installed")
	}
	root := repoRoot(t)

	// `meta skuid "xray"` is resolved to a numeric uid when nft PARSES the
	// file, so validating verbatim only works where the gateway is installed.
	// On a CI runner that fails with "User does not exist" — a fact about the
	// environment, not a defect in the ruleset. The real username is asserted
	// separately by TestLoopGuardNamesTheXrayUser, so this cannot hide the rule
	// going missing.
	unprivileged := os.Geteuid() != 0
	if unprivileged && exec.Command("unshare", "-rn", "true").Run() != nil {
		t.Skip("not root and no unprivileged user namespaces available")
	}

	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			t.Chdir(root)
			cfg := loadFixture(t, name)
			ruleset, err := NFT(cfg, fixedTime)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			path := filepath.Join(t.TempDir(), "gateway.nft")
			checkable := strings.ReplaceAll(ruleset, `meta skuid "xray"`, `meta skuid "root"`)
			if err := os.WriteFile(path, []byte(checkable), 0o600); err != nil {
				t.Fatal(err)
			}

			args := []string{nft, "-c", "-f", path}
			if unprivileged {
				args = append([]string{"unshare", "-rn"}, args...)
			}
			out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
			if err != nil {
				t.Errorf("nft rejected the ruleset: %v\n%s", err, out)
			} else if len(out) > 0 {
				t.Errorf("nft accepted the ruleset but complained:\n%s", out)
			}
		})
	}
}

// The output chain returns early on the xray uid. That exemption is one half of
// the loop guard — the other is sockopt.mark on every outbound — and without it
// the box routes its own tunnel traffic back into the tunnel.
func TestLoopGuardNamesTheXrayUser(t *testing.T) {
	root := repoRoot(t)
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			t.Chdir(root)
			ruleset, err := NFT(loadFixture(t, name), fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ruleset, `meta skuid "xray"`) {
				t.Error(`the output chain no longer exempts the xray uid — ` +
					`Xray's own packets become eligible for TPROXY`)
			}
		})
	}
}
