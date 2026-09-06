package gateway

import (
	"io/fs"
	"testing"
)

func TestEmbeddedTemplates(t *testing.T) {
	n := 0
	fs.WalkDir(Templates, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	t.Logf("%d embedded template files", n)
	for _, want := range []string{
		"templates/gateway.nft.tmpl",
		"templates/sysctl.conf.tmpl",
		"templates/wan.network.tmpl",
		// Two-armed boxes only, but embedded unconditionally: a binary that
		// cannot render the LAN side is one that fails at `gw apply`, on the
		// box, with the office already replugged.
		"templates/lan.network.tmpl",
		"templates/systemd/xray.service",
		"templates/lib/health.sh",
	} {
		if _, err := Templates.ReadFile(want); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
}
