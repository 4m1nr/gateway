package render

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/config"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current output")

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func fixtureNames(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoRoot(t), "tests/fixtures/*.toml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, strings.TrimSuffix(filepath.Base(p), ".toml"))
	}
	return out
}

func loadFixture(t *testing.T, name string) *config.Config {
	t.Helper()
	cfg, err := config.Load(filepath.Join(repoRoot(t), "tests/fixtures", name+".toml"))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return cfg
}

// The Xray config is the highest-consequence generated file: its routing rules
// are matched first-to-last, so rule ORDER is the behaviour. Comparing against
// output frozen from the Python renderer catches a reordering that no
// structural assertion would notice.
func TestXrayConfigMatchesGolden(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			cfg := loadFixture(t, name)
			got, err := RenderXray(cfg)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			goldenPath := filepath.Join(repoRoot(t), "tests/testdata/golden", name,
				"usr/local/etc/xray/config.json")
			compareGolden(t, goldenPath, got)
		})
	}
}

// compareGolden diffs against the recorded file, or rewrites it under -update.
func compareGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v", path, err)
	}
	if string(got) == string(want) {
		return
	}
	t.Errorf("output differs from %s\n%s", path, lineDiff(string(want), string(got)))
}

// lineDiff reports the first differing lines with a little context, which is
// far more useful for a 400-line config than dumping both versions.
func lineDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	var b strings.Builder
	shown := 0
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w == g {
			continue
		}
		b.WriteString("  line " + itoa(i+1) + ":\n    want: " + w + "\n    got:  " + g + "\n")
		if shown++; shown >= 10 {
			b.WriteString("  ... (further differences suppressed)\n")
			break
		}
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
