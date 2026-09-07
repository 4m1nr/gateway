package config

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

// ClientsBy returns the addresses of clients assigned the given policy.
func (c *Config) ClientsBy(policy string) []string {
	var out []string
	for _, cl := range c.Clients {
		if cl.Policy == policy {
			out = append(out, cl.IP)
		}
	}
	return out
}

// IsDomainServer reports whether the main outbound reaches its server by name
// rather than by address. A named server has to be resolvable before the tunnel
// exists, which is why it gets its own DNS rule.
func (c *Config) IsDomainServer() bool {
	addr := c.Server.Address
	if addr == "" {
		return false
	}
	_, err := netip.ParseAddr(addr)
	return err != nil
}

// ProxySources are the addresses whose traffic is intercepted: plain proxy
// clients and every profile client, since splitting a profile by destination
// requires Xray to see the traffic. Plus the tailnet when exit-node egress is
// intercepted.
func (c *Config) ProxySources() []string {
	var out []string
	for _, cl := range c.Clients {
		if c.Intercepted[cl.Policy] {
			out = append(out, cl.IP)
		}
	}
	if c.TSEnabled && c.Intercepted[c.TSExitPolicy] {
		out = append(out, TailnetV4)
	}
	return out
}

// TailnetBlocked reports whether exit-node traffic is dropped outright.
func (c *Config) TailnetBlocked() bool {
	return c.TSEnabled && c.TSExitPolicy == "block"
}

// TailnetDirect reports whether exit-node traffic bypasses the tunnel.
func (c *Config) TailnetDirect() bool {
	return c.TSEnabled && c.TSExitPolicy == "direct"
}

// ProfileSources are the source addresses a profile applies to. When the
// profile is also the LAN default, that includes every unlisted device; when it
// is the exit-node policy, it includes the tailnet.
func (c *Config) ProfileSources(name string) []string {
	srcs := c.ClientsBy(name)
	if c.DefaultPolicy == name {
		// Every network this gateway serves, not just the attached one: a
		// device in a zone reaches Xray the same way and must match the same
		// rule, or the default policy silently stops at the segment boundary.
		srcs = append(srcs, c.LANNetworks()...)
	}
	if c.TSEnabled && c.TSExitPolicy == name {
		srcs = append(srcs, TailnetV4)
	}
	return srcs
}

// BypassDst are destinations that must never enter the tunnel: local scopes,
// the tailnet, and RFC1918 as a whole. Used by the output chain, where the
// box's own traffic to a private address is local business.
func (c *Config) BypassDst() []string {
	return append([]string(nil), ReservedDst...)
}

// LANNetworks is every subnet this gateway serves: the directly attached one,
// plus every routed zone. It is what "the LAN" means anywhere the answer has to
// include devices that are not on this box's own segment.
//
// With no zones it is exactly [lan_cidr], so everything downstream renders as
// it always did.
func (c *Config) LANNetworks() []string {
	if len(c.Zones) == 0 {
		return []string{c.LANCidr}
	}
	out := []netip.Prefix{c.LAN}
	for _, z := range c.Zones {
		out = append(out, z.Prefix)
	}
	return collapsePrefixes(out)
}

// servesAddr reports whether an address is on a network this gateway serves.
func (c *Config) servesAddr(addr netip.Addr) bool {
	if c.LAN.Contains(addr) {
		return true
	}
	for _, z := range c.Zones {
		if z.Prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// zoneHint names the zones in an "outside the LAN" error, so the reader is not
// left wondering whether zones were meant to count.
func zoneHint(zones []Zone) string {
	if len(zones) == 0 {
		return ""
	}
	names := make([]string, 0, len(zones))
	for _, z := range zones {
		names = append(names, z.CIDR)
	}
	return " or any net.zone (" + strings.Join(names, ", ") + ")"
}

// NetworkLinks maps each interface this config addresses to the address it
// should carry, as "10.0.0.2/24". An empty value means the address comes from a
// lease and nothing may be assumed about it.
//
// Apply uses this to leave a renumbered card holding one address rather than
// two: networkd adds the new one and keeps the old.
func (c *Config) NetworkLinks() map[string]string {
	links := map[string]string{}
	if c.WANDHCP {
		links[c.WANIf] = ""
	} else {
		links[c.WANIf] = fmt.Sprintf("%s/%d", c.WANIP, c.WANPrefixLen)
	}
	if c.TwoArm {
		links[c.LANIf] = fmt.Sprintf("%s/%d", c.BoxIP, c.PrefixLen)
	}
	return links
}

// RoutedPrivate is private space that routing deliberately sends somewhere.
//
// A profile route or a custom rule naming an RFC1918 range — a work network
// behind an upstream, say — is a statement that those addresses are reached
// through that outbound. Both of the firewall's blanket rules about private
// space would otherwise defeat it: the poisoned-DNS drop kills the traffic
// outright, and the local-business bypass sends it out of the WAN instead of
// into the tunnel. Xray's rule is then correct and never consulted, because
// the packets never reach Xray.
//
// Only literal prefixes count. A geoip: tag names a file this cannot read.
func (c *Config) RoutedPrivate() []string {
	var out []netip.Prefix
	add := func(raw string) {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			if a, aerr := netip.ParseAddr(strings.TrimSpace(raw)); aerr == nil {
				p = netip.PrefixFrom(a, a.BitLen())
			} else {
				return // a geoip: tag, or something Xray understands and this does not
			}
		}
		p = p.Masked()
		if !p.Addr().Is4() || !p.Addr().IsPrivate() {
			return // only RFC1918 is caught by the rules this works around
		}
		out = append(out, p)
	}

	for _, prof := range c.Profiles {
		for _, r := range prof.Routes {
			for _, ip := range r.IPs {
				add(ip)
			}
		}
	}
	for _, r := range c.Routes {
		if ips, ok := r.Rule.GetArray("ip"); ok {
			for _, v := range ips {
				if s, ok := v.(string); ok {
					add(s)
				}
			}
		}
	}
	// An upstream's declared resolver is an address that upstream serves. It
	// needs the same carve-out as any other private destination routed there,
	// or the box asks it over the WAN and never reaches it.
	for _, u := range c.Upstreams {
		if u.DNS != "" {
			add(u.DNS)
		}
	}

	return collapsePrefixes(out)
}

// collapsePrefixes drops any prefix another one already covers.
//
// nftables interval sets reject overlapping elements outright — the ruleset
// does not load at all — and an upstream's resolver almost always sits inside
// the range that upstream serves, so this is the normal case rather than a
// corner one. Exact duplicates go the same way: the same range named by two
// profiles is one range.
func collapsePrefixes(in []netip.Prefix) []string {
	// Broadest first, so the prefix that covers the others is always the one
	// already kept when they are examined.
	sorted := append([]netip.Prefix(nil), in...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Bits() != sorted[j].Bits() {
			return sorted[i].Bits() < sorted[j].Bits()
		}
		return sorted[i].Addr().Less(sorted[j].Addr())
	})

	var kept []netip.Prefix
	for _, p := range sorted {
		covered := false
		for _, k := range kept {
			if subnetOf(p, k) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, p)
		}
	}

	sortPrefixes(kept)
	out := make([]string, 0, len(kept))
	for _, p := range kept {
		out = append(out, p.String())
	}
	return out
}

// PoisonedDst is RFC1918 space that is NOT reachable from here.
//
// A filtering resolver answers a blocked name with a private address
// (10.10.34.34 and relatives). A client then sends real traffic there.
// Bypassing it — which is what treating all of RFC1918 as "local" does — drops
// that traffic into a black hole with no counter and no log, and the symptom is
// "this one site does not load" with everything else fine.
//
// Computed as RFC1918 minus what is genuinely local, so it can never match
// traffic to this LAN or to a network named in routing.extra_local_networks.
func (c *Config) PoisonedDst() []string {
	if !c.DropPrivate {
		return nil
	}
	blocks := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	keep := []netip.Prefix{c.LAN}
	// A routed zone is private space that IS local here — it is behind a router
	// on this segment, and this box has a route to it. Left in the drop set,
	// every device in it would be treated as a poisoned DNS answer.
	for _, z := range c.Zones {
		keep = append(keep, z.Prefix)
	}
	// Two-armed, the uplink segment is a second network this box is genuinely
	// on. Dropping traffic to it as a poisoned answer would black-hole the
	// office modem's own address — and under DHCP we do not know the segment,
	// which is what routing.extra_local_networks is for.
	if c.WANCidr != "" && c.WANCidr != c.LANCidr {
		if p, err := netip.ParsePrefix(c.WANCidr); err == nil {
			keep = append(keep, p.Masked())
		}
	}
	for _, cidr := range c.ExtraLocal {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			keep = append(keep, p.Masked())
		}
	}
	// Not local, but not poisoned either: routing has somewhere to send these,
	// so dropping them would break the route that names them.
	for _, cidr := range c.RoutedPrivate() {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			keep = append(keep, p.Masked())
		}
	}

	for _, local := range keep {
		var next []netip.Prefix
		for _, block := range blocks {
			switch {
			case subnetOf(local, block):
				next = append(next, addressExclude(block, local)...)
			case !subnetOf(block, local):
				next = append(next, block)
			}
			// A block entirely inside `local` is dropped: it is all reachable.
		}
		blocks = next
	}

	sortPrefixes(blocks)
	out := make([]string, 0, len(blocks))
	for _, b := range blocks {
		out = append(out, b.String())
	}
	return out
}

// overlaps reports whether two prefixes share any address at all.
func overlaps(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}

// summarises reports whether outer STRICTLY contains inner — a summary route,
// which longest-prefix match resolves without ambiguity, rather than an overlap
// the kernel would have to guess about. Equal prefixes are not a summary.
func summarises(outer, inner netip.Prefix) bool {
	return outer.Bits() < inner.Bits() && outer.Contains(inner.Addr())
}

// summaryOf names the smallest useful supernet of a prefix, for the error that
// suggests one.
func summaryOf(p netip.Prefix) string {
	if p.Bits() <= 8 || !p.Addr().Is4() {
		return "a broader prefix"
	}
	return netip.PrefixFrom(p.Addr(), p.Bits()-8).Masked().String()
}

// subnetOf reports whether inner lies entirely within outer.
func subnetOf(inner, outer netip.Prefix) bool {
	return inner.Bits() >= outer.Bits() && outer.Contains(inner.Addr())
}

// AllOutbounds returns the main server, the fallback if configured, and every
// upstream, in the order the Xray config lists them.
func (c *Config) AllOutbounds() []*Outbound {
	out := []*Outbound{c.Server}
	if c.Fallback != nil {
		out = append(out, c.Fallback)
	}
	for _, u := range c.Upstreams {
		out = append(out, u.Outbound)
	}
	return out
}

// ProfileNames returns profile names in config order.
func (c *Config) ProfileNames() []string { return profileNames(c.Profiles) }

// UpstreamNames returns upstream names in config order.
func (c *Config) UpstreamNames() []string {
	out := make([]string, 0, len(c.Upstreams))
	for _, u := range c.Upstreams {
		out = append(out, u.Name)
	}
	return out
}

// isIPLiteral reports whether a value is a bare IP address.
func isIPLiteral(value string) bool {
	_, err := netip.ParseAddr(strings.TrimSpace(value))
	return err == nil
}

// UpstreamByTag finds an upstream by its Xray outbound tag.
func (c *Config) UpstreamByTag(tag string) *Upstream {
	for _, u := range c.Upstreams {
		if u.Outbound.Tag == tag {
			return u
		}
	}
	return nil
}
