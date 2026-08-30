package render

import (
	"fmt"
	"strings"

	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/jsonx"
)

// adguardDomain turns an Xray domain rule into an AdGuard domain specifier.
//
// AdGuard matches a bare name and everything under it, which is what
// "domain:" means in Xray -- so git.amnafzar.ir follows amnafzar.ir, the case
// this exists for. The forms with no AdGuard equivalent are skipped rather
// than approximated: a geosite: list names thousands of domains, and turning a
// regexp into a suffix would silently redirect names nobody asked to redirect.
func adguardDomain(spec string) string {
	switch {
	case strings.HasPrefix(spec, "domain:"):
		return strings.TrimPrefix(spec, "domain:")
	case strings.HasPrefix(spec, "full:"):
		return strings.TrimPrefix(spec, "full:")
	case strings.ContainsAny(spec, ":"):
		return "" // geosite:, regexp:, ext: -- not expressible here
	default:
		return spec
	}
}

// AdGuardOverrides is the AdGuard Home settings the gateway owns.
//
// AdGuard owns its own YAML — it rewrites and schema-migrates the file — so we
// do not template it wholesale. We emit the keys we care about and merge them
// in, which leaves anything set through its web UI intact across `gw apply`.
func AdGuardOverrides(c *config.Config) *jsonx.Object {
	// Domestic names go to the direct resolvers; everything else to DoH, which
	// rides the tunnel because AdGuard's own egress is captured by the OUTPUT
	// chain like any other local process.
	var upstreams []any

	// Names a profile sends through an upstream, resolved by that upstream's
	// own resolver.
	//
	// This is the half that Xray's DNS routing cannot reach: a client asks
	// AdGuard, and AdGuard answers from its own upstreams, which know nothing
	// about profiles. Without an entry here a corporate name matches the
	// domestic [/ir/] rule below and comes back as the public address or
	// NXDOMAIN -- the routing rule for it is then correct and never has an
	// address to act on. AdGuard picks the most specific domain match, so
	// [/amnafzar.ir/] beats [/ir/] regardless of order; first anyway, because
	// the order is what a person reads.
	for _, group := range dnsThroughUpstream(c) {
		up := c.UpstreamByTag(group.tag)
		if up == nil || up.DNS == "" {
			continue
		}
		for _, spec := range group.domains {
			if name := adguardDomain(spec); name != "" {
				upstreams = append(upstreams, fmt.Sprintf("[/%s/]%s", name, up.DNS))
			}
		}
	}

	for _, suffix := range c.DirectSuffixes {
		for _, res := range c.UpDirect {
			upstreams = append(upstreams, fmt.Sprintf("[/%s/]%s", suffix, res))
		}
	}
	for _, u := range c.UpProxied {
		upstreams = append(upstreams, u)
	}
	if upstreams == nil {
		upstreams = []any{}
	}

	persistent := []any{}
	for _, cl := range c.Clients {
		persistent = append(persistent, obj(
			"name", cl.Name,
			"ids", arr(cl.IP),
			"tags", []any{},
			"use_global_settings", true,
			"use_global_blocked_services", true,
			"filtering_enabled", cl.Policy != "direct",
			"safebrowsing_enabled", false,
			"parental_enabled", false,
			"blocked_services", obj(
				"ids", []any{},
				"schedule", obj("time_zone", c.Timezone),
			),
			"upstreams", []any{},
			"ignore_querylog", false,
			"ignore_statistics", false,
		))
	}

	filters := []any{}
	for i, url := range c.Blocklists {
		name := url
		if idx := lastIndexByte(url, '/'); idx >= 0 {
			name = url[idx+1:]
		}
		filters = append(filters, obj(
			"enabled", true,
			"url", url,
			"name", name,
			"id", num(1000+i),
		))
	}

	return obj(
		"http", obj(
			// Reachable on the LAN and over Tailscale; the input chain is what
			// keeps it off anything else.
			"address", fmt.Sprintf("0.0.0.0:%d", c.UIPort),
		),
		"dns", obj(
			"bind_hosts", arr("0.0.0.0"),
			"port", num(c.DNSPort),
			"upstream_dns", upstreams,
			"bootstrap_dns", strs(c.Bootstrap),
			// Deliberately empty. Falling back to the domestic resolvers means
			// that whenever DoH is slow — which is exactly when the network is
			// being interfered with — AdGuard asks a resolver that lies, and
			// cheerfully caches the lie. A poisoned answer pointing at private
			// space (10.10.34.34 and friends) is worse than no answer: that
			// address is in bypass_dst, so the connection is never intercepted,
			// goes out direct, and dies mid-TLS-handshake looking like a broken
			// tunnel. Fail closed on DNS, like everything else here.
			"fallback_dns", []any{},
			"upstream_mode", "load_balance",
			"ratelimit", num(0),
			"enable_dnssec", true,
			"cache_size", num(8388608),
			"cache_ttl_min", num(60),
			"aaaa_disabled", c.IPv6Mode == "off",
			"local_ptr_upstreams", strs(c.UpDirect),
		),
		"querylog", obj(
			"enabled", true,
			// Thin-client flash is small and slow; keep retention short.
			"interval", fmt.Sprintf("%dh", c.QuerylogDays*24),
			"size_memory", num(1000),
		),
		"statistics", obj(
			"enabled", true,
			"interval", fmt.Sprintf("%dh", c.StatslogDays*24),
		),
		"filters", filters,
		"clients", obj("persistent", persistent),
		"filtering", obj("protection_enabled", true, "filtering_enabled", true),
	)
}

func lastIndexByte(s string, b byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == b {
			return i
		}
	}
	return -1
}
