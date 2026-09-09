package check

import (
	"reflect"
	"testing"
)

// A card holding both the configured address and a DHCP client's IPv4LL
// fallback. Before the split, the second address read as a renumbering leftover
// and the report told the reader to run `gw apply` — which deletes it, after
// which the client puts a fresh one back and the same check fails again.
func TestSplitLinkLocalSeparatesASquattedAddress(t *testing.T) {
	configured, linkLocal := splitLinkLocal([]string{
		"172.30.4.3/24", "169.254.135.86/16",
	})
	if want := []string{"172.30.4.3/24"}; !reflect.DeepEqual(configured, want) {
		t.Errorf("configured = %v, want %v", configured, want)
	}
	if want := []string{"169.254.135.86/16"}; !reflect.DeepEqual(linkLocal, want) {
		t.Errorf("linkLocal = %v, want %v", linkLocal, want)
	}
}

// With the link-local address set aside, one configured address is the healthy
// case again rather than "more than one address".
func TestSplitLinkLocalLeavesTheHealthyCaseSingle(t *testing.T) {
	configured, linkLocal := splitLinkLocal([]string{"172.30.4.3/24", "169.254.11.182/16"})
	if len(configured) != 1 {
		t.Fatalf("configured = %v, want exactly one address", configured)
	}
	if !containsAddr(configured, "172.30.4.3") {
		t.Errorf("configured = %v, want it to carry the box address", configured)
	}
	if len(linkLocal) != 1 {
		t.Errorf("linkLocal = %v, want the squatted address held back", linkLocal)
	}
}

// Two real addresses are still a renumbering leftover, which is a different
// fault with a different fix.
func TestSplitLinkLocalKeepsARenumberingLeftover(t *testing.T) {
	configured, linkLocal := splitLinkLocal([]string{"192.168.1.2/24", "192.168.1.9/24"})
	if len(configured) != 2 {
		t.Errorf("configured = %v, want both addresses judged", configured)
	}
	if linkLocal != nil {
		t.Errorf("linkLocal = %v, want none", linkLocal)
	}
}

func TestIsLinkLocal(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want bool
	}{
		{"169.254.135.86/16", true},
		{"172.30.4.3/24", false},
		{"169.253.0.1/16", false},
		{"", false},
	} {
		if got := isLinkLocal(tc.cidr); got != tc.want {
			t.Errorf("isLinkLocal(%q) = %v, want %v", tc.cidr, got, tc.want)
		}
	}
}
