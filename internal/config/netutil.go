package config

import (
	"net/netip"
	"sort"
)

// parseAddr accepts a bare IP address.
func parseAddr(value, where string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, errf("%s: %q is not a valid IP address", where, value)
	}
	return addr, nil
}

// parsePrefix accepts a CIDR, or a bare address as a host route. Python's
// ipaddress.ip_network(strict=False) accepts both and masks host bits off;
// netip.ParsePrefix does neither, so both behaviours are restored here.
func parsePrefix(value, where string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Masked(), nil
	}
	if a, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	return netip.Prefix{}, errf("%s: %q is not a valid CIDR", where, value)
}

// addressExclude returns block minus hole, as the smallest set of prefixes that
// covers the difference. hole must be contained in block.
//
// This is what keeps the poisoned-DNS drop from swallowing the LAN: RFC1918 as
// a whole, minus the networks that are genuinely reachable here.
func addressExclude(block, hole netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for block.Bits() < hole.Bits() {
		// Split block in two and keep the half that does not contain hole.
		lo := netip.PrefixFrom(block.Addr(), block.Bits()+1).Masked()
		hi := netip.PrefixFrom(nextSibling(lo), block.Bits()+1).Masked()
		if lo.Overlaps(hole) {
			out = append(out, hi)
			block = lo
		} else {
			out = append(out, lo)
			block = hi
		}
	}
	return out
}

// nextSibling returns the first address after the given prefix, which is the
// base of its sibling at the same length.
func nextSibling(p netip.Prefix) netip.Addr {
	addr := p.Addr()
	bytes := addr.AsSlice()
	// Add 1 at the bit position just past the prefix length.
	bit := p.Bits()
	idx := (bit - 1) / 8
	if bit == 0 {
		return addr
	}
	bytes[idx] += 1 << (7 - uint((bit-1)%8))
	next, _ := netip.AddrFromSlice(bytes)
	return next
}

// sortPrefixes orders by network address then prefix length, matching the
// Python renderer so generated set elements land in the same order.
func sortPrefixes(nets []netip.Prefix) {
	sort.Slice(nets, func(i, j int) bool {
		if c := nets[i].Addr().Compare(nets[j].Addr()); c != 0 {
			return c < 0
		}
		return nets[i].Bits() < nets[j].Bits()
	})
}
