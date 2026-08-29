package render

import (
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/am1nr/gateway/internal/config"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current output")

// testRoot is resolved at init, before any test calls t.Chdir — resolving it
// lazily would give a different answer depending on which test ran first.
var testRoot = func() string {
	dir, err := filepath.Abs("../..")
	if err != nil {
		panic(err)
	}
	return dir
}()

func repoRoot(t *testing.T) string {
	t.Helper()
	return testRoot
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

// goldenRoot is where the Python renderer's frozen output lives. Two values in
// the tree are not reproducible — the timestamp in the nftables header and the
// absolute repo path — so both sides are normalised before comparing.
const (
	generatedAtToken = "@GENERATED_AT@"
	repoToken        = "@REPO@"
)

// fixedTime is the timestamp Build stamps into the nftables header under test.
var fixedTime = time.Date(2026, 8, 29, 0, 30, 5, 0, time.FixedZone("", 3*3600+1800))

var timestampRE = regexp.MustCompile(` at 20\d\d-\d\d-\d\dT[\d:]+[+-][\d:]+`)

// normalise replaces the two values that legitimately differ per render.
func normalise(text, repo string) string {
	text = timestampRE.ReplaceAllString(text, " at "+generatedAtToken)
	return strings.ReplaceAll(text, repo, repoToken)
}

// The whole staging tree must match what the Python renderer produced, file for
// file and mode for mode. This is the acceptance test for the migration: the
// Python is not deleted until it passes.
func TestBuildTreeMatchesGolden(t *testing.T) {
	root := repoRoot(t)
	modes := loadModes(t, filepath.Join(root, "tests/testdata/golden-modes.txt"))

	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			// The goldens were rendered from the repo root with a relative
			// config path, and the nftables header quotes that path back. Doing
			// the same here reproduces it exactly, and exercises resolving an
			// outbound's `file` relative to the config rather than the cwd.
			t.Chdir(root)
			cfg, err := config.Load(filepath.Join("tests/fixtures", name+".toml"))
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			files, err := Build(cfg, Options{Repo: root, GeneratedAt: fixedTime})
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			goldenDir := filepath.Join(root, "tests/testdata/golden", name)
			got := map[string]File{}
			for _, f := range files {
				got[f.Path] = f
			}

			want, err := treeFiles(goldenDir)
			if err != nil {
				t.Fatalf("reading golden tree: %v", err)
			}

			for _, rel := range want {
				f, ok := got[rel]
				if !ok {
					t.Errorf("%s is in the golden tree but was not rendered", rel)
					continue
				}
				raw, err := os.ReadFile(filepath.Join(goldenDir, rel))
				if err != nil {
					t.Fatal(err)
				}
				if g := normalise(f.Content, root); g != string(raw) {
					t.Errorf("%s differs:\n%s", rel, lineDiff(string(raw), g))
				}
				if wantMode, ok := modes[name+"/"+rel]; ok && f.Mode.Perm() != wantMode {
					t.Errorf("%s has mode %04o, want %04o", rel, f.Mode.Perm(), wantMode)
				}
			}
			for rel := range got {
				if !containsStr(want, rel) {
					t.Errorf("%s was rendered but is not in the golden tree", rel)
				}
			}
		})
	}
}

func treeFiles(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		out = append(out, rel)
		return nil
	})
	sort.Strings(out)
	return out, err
}

// loadModes reads the recorded permissions, so a job script that stops being
// 0700 is caught here rather than on the box.
func loadModes(t *testing.T, path string) map[string]os.FileMode {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mode manifest: %v", err)
	}
	out := map[string]os.FileMode{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			continue
		}
		n, err := strconv.ParseUint(parts[1], 8, 32)
		if err != nil {
			continue
		}
		out[parts[0]+"/"+parts[2]] = os.FileMode(n)
	}
	return out
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
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
