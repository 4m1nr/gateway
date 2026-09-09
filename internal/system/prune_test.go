package system

import (
	"reflect"
	"testing"
)

// Real `ip -4 -o addr show dev enp3s0 scope global` output from a box where a
// leftover dhcpcd was still managing the LAN card alongside networkd. The
// link-local address is listed as "scope global noprefixroute", which is why it
// arrives here at all.
const squattedLink = `3: enp3s0    inet 172.30.4.3/24 brd 172.30.4.255 scope global enp3s0\       valid_lft forever preferred_lft forever
3: enp3s0    inet 169.254.135.86/16 brd 169.254.255.255 scope global noprefixroute enp3s0\       valid_lft forever preferred_lft forever`

// A link-local address belongs to a live DHCP client, not to this config.
// Deleting it does not stick — the client re-adds it seconds later — so every
// apply would report a removal that did not happen and bury the real fault.
func TestStaleAddrsLeavesLinkLocalAlone(t *testing.T) {
	if got := staleAddrs(squattedLink, "172.30.4.3/24"); got != nil {
		t.Fatalf("staleAddrs = %v, want none: the 169.254 address is not ours to delete", got)
	}
}

// The case pruning exists for still works: an address from an earlier
// renumbering that the config no longer names.
func TestStaleAddrsRemovesARenumberingLeftover(t *testing.T) {
	out := `3: eth0    inet 192.168.1.2/24 brd 192.168.1.255 scope global eth0\       valid_lft forever preferred_lft forever
3: eth0    inet 192.168.1.9/24 brd 192.168.1.255 scope global secondary eth0\       valid_lft forever preferred_lft forever`
	want := []string{"192.168.1.9/24"}
	if got := staleAddrs(out, "192.168.1.2/24"); !reflect.DeepEqual(got, want) {
		t.Fatalf("staleAddrs = %v, want %v", got, want)
	}
}

// A leased address has no configured value to judge it against, and deleting it
// would cut the uplink on a box running wan_dhcp.
func TestStaleAddrsLeavesALeaseAlone(t *testing.T) {
	out := `2: enp5s0    inet 217.11.23.197/28 brd 217.11.23.207 scope global dynamic enp5s0\       valid_lft 3421sec preferred_lft 3421sec`
	if got := staleAddrs(out, ""); got != nil {
		t.Fatalf("staleAddrs = %v, want none: a lease is not a leftover", got)
	}
}

func TestIsLinkLocal(t *testing.T) {
	for _, tc := range []struct {
		cidr string
		want bool
	}{
		{"169.254.135.86/16", true},
		{"169.254.0.1/16", true},
		{"172.30.4.3/24", false},
		{"192.168.1.2/24", false},
		{"169.253.0.1/16", false},
		{"not an address", false},
	} {
		if got := isLinkLocal(tc.cidr); got != tc.want {
			t.Errorf("isLinkLocal(%q) = %v, want %v", tc.cidr, got, tc.want)
		}
	}
}
