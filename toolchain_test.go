package gateway

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// maxToolchain is the newest Go the gateway may require.
//
// Debian 13 ships Go 1.24, and the box builds with the distro package — there
// is no second toolchain on a thin client and no reliable way to fetch one when
// the tunnel it is meant to build is down. A dependency that requires anything
// newer does not fail here; it fails on the box, mid-migration, at the exact
// moment `gw` has already been deleted and cannot be rebuilt.
const maxToolchain = "1.24"

var goDirectiveRE = regexp.MustCompile(`(?m)^go (\d+)\.(\d+)`)
var vendorGoRE = regexp.MustCompile(`## explicit; go (\d+)\.(\d+)`)

// TestModuleTargetsTheDistroToolchain guards go.mod's own directive.
func TestModuleTargetsTheDistroToolchain(t *testing.T) {
	raw, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := goDirectiveRE.FindSubmatch(raw)
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	got := string(m[1]) + "." + string(m[2])
	if newerThan(got, maxToolchain) {
		t.Errorf("go.mod requires Go %s, but the box has %s. `go get` raises this "+
			"directive silently when a dependency demands it.", got, maxToolchain)
	}
}

// TestNoDependencyOutgrowsTheToolchain is the one that would have caught the
// failure on the box.
//
// Lowering go.mod's own directive does NOT make a dependency requiring a newer
// Go build — it only lowers the language version for this module's code. The
// requirement that actually stops the build is recorded per-module in
// vendor/modules.txt, and it is invisible unless you build with the toolchain
// the box really has.
func TestNoDependencyOutgrowsTheToolchain(t *testing.T) {
	raw, err := os.ReadFile("vendor/modules.txt")
	if err != nil {
		t.Skip("not vendored")
	}
	lines := strings.Split(string(raw), "\n")
	var module string
	for _, line := range lines {
		if strings.HasPrefix(line, "# ") && !strings.HasPrefix(line, "## ") {
			module = strings.TrimPrefix(line, "# ")
			continue
		}
		m := vendorGoRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		got := m[1] + "." + m[2]
		if newerThan(got, maxToolchain) {
			t.Errorf("%s requires Go %s, but the box builds with %s.\n"+
				"Pin it to a version whose go directive is %s or lower, then re-vendor.",
				module, got, maxToolchain, maxToolchain)
		}
	}
}

// newerThan compares two "major.minor" versions.
func newerThan(a, b string) bool {
	aMaj, aMin := split(a)
	bMaj, bMin := split(b)
	if aMaj != bMaj {
		return aMaj > bMaj
	}
	return aMin > bMin
}

func split(v string) (int, int) {
	major, minor, _ := strings.Cut(v, ".")
	a, _ := strconv.Atoi(major)
	b, _ := strconv.Atoi(minor)
	return a, b
}
