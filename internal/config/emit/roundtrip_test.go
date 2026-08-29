package emit_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/config/emit"
	"github.com/am1nr/gateway/internal/render"
)

var repoRoot = func() string {
	dir, err := filepath.Abs("../../..")
	if err != nil {
		panic(err)
	}
	return dir
}()

var fixedTime = time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC)

func fixtures(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoRoot, "tests/fixtures/*.toml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	return paths
}

// The acceptance test for owning the file.
//
// A save rewrites gateway.toml whole, so the only thing that makes that safe is
// this: read a config, write it back, read it again, and the gateway it
// describes must be the same gateway. Anything less means the dashboard can
// change what the box does just by saving something unrelated.
//
// "The same gateway", not "the same bytes", for one reason. A [[route]] table
// IS an Xray rule, and the loader preserves the key order it was written in;
// the emitter writes a canonical order. So the first rewrite of a hand-edited
// file can reorder the keys within a rule — which Xray does not care about,
// while the order of the rules themselves, which it does care about, is
// preserved and checked. Generated files that are not JSON are still compared
// byte for byte, and TestEmitIsIdempotent covers stability from then on.
func TestRoundTripRendersAnIdenticalGateway(t *testing.T) {
	for _, path := range fixtures(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		t.Run(name, func(t *testing.T) {
			t.Chdir(repoRoot)
			rel := filepath.Join("tests/fixtures", name+".toml")

			before, err := config.Load(rel)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			originalFiles, err := render.Build(before, render.Options{
				Repo: repoRoot, GeneratedAt: fixedTime,
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}

			// Write it back out, beside the fixtures so relative outbound paths
			// still resolve, and read it again.
			var doc emit.Document
			raw, err := os.ReadFile(rel)
			if err != nil {
				t.Fatal(err)
			}
			if err := toml.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			out, err := emit.Emit(doc)
			if err != nil {
				t.Fatalf("emit: %v", err)
			}

			rewritten := filepath.Join("tests", "fixtures", ".rt-"+name+".toml")
			if err := os.WriteFile(rewritten, out, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(rewritten) })

			after, err := config.Load(rewritten)
			if err != nil {
				t.Fatalf("the rewritten config does not load: %v\n\n%s", err, out)
			}
			rewrittenFiles, err := render.Build(after, render.Options{
				Repo: repoRoot, GeneratedAt: fixedTime,
			})
			if err != nil {
				t.Fatalf("render after round trip: %v", err)
			}

			compareTrees(t, originalFiles, rewrittenFiles, string(out))
		})
	}
}

// compareTrees reports the first generated file that differs.
func compareTrees(t *testing.T, want, got []render.File, emitted string) {
	t.Helper()
	index := map[string]render.File{}
	for _, f := range got {
		index[f.Path] = f
	}
	if len(want) != len(got) {
		t.Errorf("round trip changed the file count: %d -> %d", len(want), len(got))
	}
	for _, w := range want {
		g, ok := index[w.Path]
		if !ok {
			t.Errorf("%s is no longer generated after a round trip", w.Path)
			continue
		}
		if g.Content == w.Content {
			continue
		}
		// The config path is quoted into the nftables header and legitimately
		// differs, because the rewritten file has a different name.
		if normalisePath(w.Content) == normalisePath(g.Content) {
			continue
		}
		// JSON is compared as a document: key order inside an object carries no
		// meaning, and array order — which does — is preserved by DeepEqual.
		if strings.HasSuffix(w.Path, ".json") {
			if sameJSON(t, w.Content, g.Content) {
				continue
			}
		}
		t.Errorf("%s differs after a round trip:\n%s\n\n--- emitted config ---\n%s",
			w.Path, firstDiff(w.Content, g.Content), emitted)
		return
	}
}

// sameJSON compares two documents structurally.
func sameJSON(t *testing.T, a, b string) bool {
	t.Helper()
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// Emitting a config that came from the emitter must produce the same bytes.
// Without this, every dashboard save would churn the file and every `gw diff`
// would show noise that means nothing.
func TestEmitIsIdempotent(t *testing.T) {
	for _, path := range fixtures(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var doc emit.Document
			if err := toml.Unmarshal(raw, &doc); err != nil {
				t.Fatal(err)
			}
			first, err := emit.Emit(doc)
			if err != nil {
				t.Fatalf("emit: %v", err)
			}

			var again emit.Document
			if err := toml.Unmarshal(first, &again); err != nil {
				t.Fatalf("the emitted config does not parse: %v", err)
			}
			second, err := emit.Emit(again)
			if err != nil {
				t.Fatalf("re-emit: %v", err)
			}

			// The header carries a timestamp, which is the one line that may
			// legitimately differ between two writes.
			if stripHeader(string(first)) != stripHeader(string(second)) {
				t.Errorf("emitting twice produced different files:\n%s",
					firstDiff(stripHeader(string(first)), stripHeader(string(second))))
			}
		})
	}
}

func stripHeader(s string) string {
	if i := strings.Index(s, "\n\n"); i >= 0 {
		return s[i:]
	}
	return s
}

func normalisePath(s string) string {
	// `from tests/fixtures/default.toml` vs `from tests/fixtures/.rt-default.toml`
	return strings.ReplaceAll(s, "/.rt-", "/")
}

func firstDiff(want, got string) string {
	wl, gl := strings.Split(want, "\n"), strings.Split(got, "\n")
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return "  line " + itoa(i+1) + ":\n   before: " + w + "\n    after: " + g
		}
	}
	return ""
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
