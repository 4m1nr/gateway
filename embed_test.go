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
		"templates/systemd/xray.service",
		"templates/lib/health.sh",
		"templates/web/app.js",
	} {
		if _, err := Templates.ReadFile(want); err != nil {
			t.Errorf("missing %s: %v", want, err)
		}
	}
}
