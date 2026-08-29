package diffutil

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestIdenticalTextHasNoHunks(t *testing.T) {
	if h := Unified("a\nb\nc\n", "a\nb\nc\n", 3); h != nil {
		t.Errorf("identical text produced %d hunks", len(h))
	}
}

func TestSingleLineChange(t *testing.T) {
	got := Format(Unified("a\nb\nc\n", "a\nB\nc\n", 1))
	want := "@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestInsertAtEnd(t *testing.T) {
	got := Format(Unified("a\n", "a\nb\n", 1))
	if !strings.Contains(got, "+b") {
		t.Errorf("insertion not reported:\n%s", got)
	}
}

func TestEmptyOldFile(t *testing.T) {
	got := Format(Unified("", "a\nb\n", 3))
	if !strings.Contains(got, "+a") || !strings.Contains(got, "+b") {
		t.Errorf("new content not reported:\n%s", got)
	}
}

// The nftables ruleset and the Xray config are the files this actually runs on,
// and a wrong diff there is worse than none — it tells you your edit did
// nothing. Cross-check against the real `diff -u` on realistic input.
func TestMatchesSystemDiff(t *testing.T) {
	diffBin, err := exec.LookPath("diff")
	if err != nil {
		t.Skip("diff is not installed")
	}
	cases := []struct{ name, a, b string }{
		{"one line", "a\nb\nc\nd\ne\n", "a\nb\nX\nd\ne\n"},
		{"two distant changes", "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n",
			"1\nX\n3\n4\n5\n6\n7\n8\n9\n10\nY\n12\n"},
		{"two adjacent changes", "1\n2\n3\n4\n5\n6\n7\n8\n",
			"1\nX\n3\n4\nY\n6\n7\n8\n"},
		{"insert a block", "a\nb\nc\n", "a\nx\ny\nz\nb\nc\n"},
		{"delete a block", "a\nb\nc\nd\ne\n", "a\ne\n"},
		{"append only", "a\nb\n", "a\nb\nc\nd\n"},
		{"prepend only", "c\nd\n", "a\nb\nc\nd\n"},
		{"whole file replaced", "a\nb\nc\n", "x\ny\nz\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			oldPath, newPath := dir+"/old", dir+"/new"
			os.WriteFile(oldPath, []byte(tc.a), 0o600)
			os.WriteFile(newPath, []byte(tc.b), 0o600)

			out, _ := exec.Command(diffBin, "-u", "--label", "old", "--label", "new",
				oldPath, newPath).Output()
			// Drop the ---/+++ header lines; Format does not emit them.
			lines := strings.SplitN(string(out), "\n", 3)
			want := ""
			if len(lines) == 3 {
				want = lines[2]
			}
			got := Format(Unified(tc.a, tc.b, 3))
			if got != want {
				t.Errorf("diff differs from `diff -u`\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}

// Line numbers drive the dashboard's diff view, so they have to be right even
// when a hunk starts mid-file.
func TestLineNumbers(t *testing.T) {
	hs := Unified("a\nb\nc\nd\ne\nf\n", "a\nb\nc\nD\ne\nf\n", 1)
	if len(hs) != 1 {
		t.Fatalf("got %d hunks, want 1", len(hs))
	}
	h := hs[0]
	if h.OldStart != 3 || h.NewStart != 3 {
		t.Errorf("hunk starts at old %d new %d, want 3/3", h.OldStart, h.NewStart)
	}
	for _, l := range h.Lines {
		switch l.Op {
		case Delete:
			if l.Text != "d" || l.OldLine != 4 || l.NewLine != 0 {
				t.Errorf("bad delete line: %+v", l)
			}
		case Insert:
			if l.Text != "D" || l.NewLine != 4 || l.OldLine != 0 {
				t.Errorf("bad insert line: %+v", l)
			}
		}
	}
}
