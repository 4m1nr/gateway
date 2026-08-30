// Package render generates every file the gateway installs, into a staging
// tree that mirrors the target filesystem. Nothing here writes to the live
// system, so rendering is always safe to run.
package render

import (
	"encoding/json"
	"net/netip"
	"strconv"

	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/jsonx"
)

// XrayConfig builds the Xray config from gateway.toml.
//
// Upstream outbounds are taken verbatim from the config — the gateway does not
// model protocols or transports, so anything Xray supports works. It only owns
// the tag (routing references it) and sockopt.mark (the loop guard), both
// enforced in the config package when the outbound is loaded.
//
// Everything else here — inbounds, DNS, routing — is generated, because it is
// derived from the rest of gateway.toml rather than supplied.
func XrayConfig(c *config.Config) *jsonx.Object {
	conf := jsonx.NewObject()
	conf.Set("log", obj("loglevel", c.LogLevel))
	conf.Set("api", obj("tag", "api", "services", arr("StatsService")))
	conf.Set("dns", xrayDNS(c))
	conf.Set("inbounds", xrayInbounds(c))
	conf.Set("outbounds", xrayOutbounds(c))
	conf.Set("routing", xrayRouting(c))

	level0 := obj(
		"handshake", num(4),
		"connIdle", num(c.ConnIdle),
		"uplinkOnly", num(0),
		"downlinkOnly", num(0),
	)
	if c.BufferSizeKB >= 0 {
		level0.Set("bufferSize", num(c.BufferSizeKB))
	}
	conf.Set("policy", obj(
		"levels", obj("0", level0),
		"system", obj("statsOutboundUplink", true, "statsOutboundDownlink", true),
	))
	conf.Set("stats", jsonx.NewObject())

	if c.Fallback != nil {
		conf.Set("burstObservatory", obj(
			"subjectSelector", arr("proxy", "fallback"),
			"pingConfig", obj(
				"destination", c.ProbeURL,
				"interval", "5m",
				"timeout", "10s",
				"sampling", num(3),
			),
		))
	}
	return conf
}

// RenderXray returns the Xray config as it is written to disk.
func RenderXray(c *config.Config) ([]byte, error) {
	return jsonx.EncodeIndented(XrayConfig(c))
}

// --------------------------------------------------------------------- dns --

func xrayDNS(c *config.Config) *jsonx.Object {
	servers := []any{}
	hosts := jsonx.NewObject()

	// Pin server addresses so the tunnel never depends on DNS to come up.
	for _, s := range c.AllOutbounds() {
		if s.ResolvedIP != "" && s.Address != "" {
			hosts.Set(s.Address, s.ResolvedIP)
		}
	}

	// The server's own domain resolves via a direct resolver — it must be
	// reachable before the tunnel exists.
	var domainServers []any
	if c.IsDomainServer() {
		domainServers = append(domainServers, "domain:"+c.Server.Address)
	}
	// Upstreams reached by name need the same treatment: their hostname must
	// resolve before any tunnel exists.
	var others []*config.Outbound
	if c.Fallback != nil {
		others = append(others, c.Fallback)
	}
	for _, u := range c.Upstreams {
		others = append(others, u.Outbound)
	}
	for _, spec := range others {
		if spec.Address != "" && spec.ResolvedIP == "" && !isIP(spec.Address) {
			domainServers = append(domainServers, "domain:"+spec.Address)
		}
	}
	if len(domainServers) > 0 {
		servers = append(servers, obj(
			"address", c.UpDirect[0],
			"domains", domainServers,
			"skipFallback", false,
		))
	}

	// An upstream's own resolver, for the names routed to that upstream. First,
	// so it wins over the domestic and DoH servers below: a corporate name that
	// falls through to a public resolver comes back with the outside view, or
	// NXDOMAIN, and the profile route then has nothing to act on.
	for _, group := range dnsThroughUpstream(c) {
		up := c.UpstreamByTag(group.tag)
		if up == nil || up.DNS == "" {
			continue // no resolver declared; the query still rides the upstream
		}
		servers = append(servers, obj(
			"address", up.DNS,
			"domains", strs(group.domains),
			"skipFallback", true,
		))
	}

	// Domestic names: direct resolver, and only trust answers that look
	// domestic.
	domestic := make([]any, 0, len(c.DirectGeosite)+len(c.DirectSuffixes))
	for _, g := range c.DirectGeosite {
		domestic = append(domestic, g)
	}
	for _, d := range c.DirectSuffixes {
		domestic = append(domestic, "domain:"+d)
	}
	for _, res := range c.UpDirect {
		servers = append(servers, obj(
			"address", res,
			"domains", domestic,
			"expectIPs", strs(c.DirectGeoIP),
			"skipFallback", true,
		))
	}

	// Everything else: DoH, which rides the tunnel like the rest of our traffic.
	for _, u := range c.UpProxied {
		servers = append(servers, u)
	}

	queryStrategy := "UseIP"
	if c.IPv6Mode == "off" {
		queryStrategy = "UseIPv4"
	}
	dns := obj(
		"servers", servers,
		"queryStrategy", queryStrategy,
		"disableCache", false,
		"tag", "dns-in",
	)
	if hosts.Len() > 0 {
		dns.Set("hosts", hosts)
	}
	return dns
}

// ---------------------------------------------------------------- inbounds --

func xrayInbounds(c *config.Config) []any {
	sniffing := obj(
		"enabled", true,
		// TPROXY hands us an IP, nothing more. Sniffing recovers the hostname
		// so geosite rules can actually match.
		"destOverride", arr("http", "tls", "quic"),
		"routeOnly", true,
	)
	in := []any{
		// Loopback-only stats API. `gw check` uses the per-outbound counters to
		// prove which path a flow actually took.
		obj(
			"tag", "api",
			"listen", "127.0.0.1",
			"port", num(c.APIPort),
			"protocol", "dokodemo-door",
			"settings", obj("address", "127.0.0.1"),
		),
		obj(
			"tag", "tproxy-in",
			"port", num(c.TproxyPort),
			"protocol", "dokodemo-door",
			"settings", obj("network", "tcp,udp", "followRedirect", true),
			"streamSettings", obj("sockopt", obj("tproxy", "tproxy")),
			"sniffing", sniffing,
		),
		obj(
			"tag", "socks-in",
			"listen", "127.0.0.1",
			"port", num(c.SocksPort),
			"protocol", "socks",
			"settings", obj("auth", "noauth", "udp", true),
			"sniffing", sniffing,
		),
		obj(
			"tag", "http-in",
			"listen", "127.0.0.1",
			"port", num(c.HTTPPort),
			"protocol", "http",
			"settings", jsonx.NewObject(),
			"sniffing", sniffing,
		),
	}
	// One per upstream, wired straight to it by an inboundTag rule. Without
	// these an upstream can only be tested through whatever routing happens to
	// send its way, so "is the work server up?" is not a question the box can
	// answer -- and a dead upstream looks like a broken profile.
	for _, u := range c.Upstreams {
		in = append(in, obj(
			"tag", upstreamInbound(u.Name),
			"listen", "127.0.0.1",
			"port", num(u.ProbePort),
			"protocol", "socks",
			"settings", obj("auth", "noauth", "udp", true),
			"sniffing", sniffing,
		))
	}
	return in
}

// upstreamInbound is the tag of an upstream's own probe inbound.
func upstreamInbound(name string) string { return "probe-" + name + "-in" }

// --------------------------------------------------------------- outbounds --

func xrayOutbounds(c *config.Config) []any {
	// Verbatim, tag and loop-guard mark already enforced at load time.
	out := make([]any, 0, len(c.Upstreams)+4)
	for _, ob := range c.AllOutbounds() {
		out = append(out, ob.Object)
	}

	domainStrategy := "UseIP"
	if c.IPv6Mode == "off" {
		domainStrategy = "UseIPv4"
	}
	out = append(out,
		obj(
			"tag", "direct",
			"protocol", "freedom",
			"settings", obj("domainStrategy", domainStrategy),
			// Generated, so the loop guard and the performance settings are
			// applied here rather than at load time. This outbound carries the
			// domestic-direct half of the split, so it wants the same tuning.
			"streamSettings", obj("sockopt", directSockopt(c)),
		),
		obj("tag", "block", "protocol", "blackhole", "settings", jsonx.NewObject()),
	)
	return out
}

func directSockopt(c *config.Config) *jsonx.Object {
	sock := obj("mark", num(c.OutboundMark))
	if c.TCPCongestion != "" {
		sock.Set("tcpcongestion", c.TCPCongestion)
	}
	if c.TCPNoDelay {
		sock.Set("tcpNoDelay", true)
	}
	return sock
}

// ----------------------------------------------------------------- routing --

// dnsTag labels Xray's own DNS queries so routing rules can match them.
const dnsTag = "dns-in"

// upstreamDomains is one upstream and the names routed to it.
type upstreamDomains struct {
	tag     string
	domains []string
}

// dnsThroughUpstream groups profile-route domains by the upstream they go to.
//
// Only upstreams: proxy and direct already resolve the way their traffic
// travels, and block has nothing to resolve.
func dnsThroughUpstream(c *config.Config) []upstreamDomains {
	byTag := map[string][]string{}
	var order []string
	for _, p := range c.Profiles {
		for _, r := range p.Routes {
			if len(r.Domains) == 0 || c.UpstreamByTag(r.Tag) == nil {
				continue
			}
			if _, seen := byTag[r.Tag]; !seen {
				order = append(order, r.Tag)
			}
			for _, d := range r.Domains {
				if !contains(byTag[r.Tag], d) {
					byTag[r.Tag] = append(byTag[r.Tag], d)
				}
			}
		}
	}
	out := make([]upstreamDomains, 0, len(order))
	for _, tag := range order {
		out = append(out, upstreamDomains{tag: tag, domains: byTag[tag]})
	}
	return out
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// tunnelTarget points a rule at the tunnel.
//
// "proxy" names the primary outbound, but what a rule usually MEANS by it is
// "through the tunnel" — and with a fallback configured the tunnel is the
// balancer, which picks between the two by observed latency. Pinning such a
// rule to the primary outbound means it alone keeps using a dead server while
// everything else fails over: a profile client would lose connectivity at
// exactly the moment the failover existed to prevent that.
//
// So every rule that says "proxy" is sent to the balancer when there is one.
// The balancer's own selector still names the outbounds, which is what makes
// them reachable at all.
func tunnelTarget(c *config.Config, rule *jsonx.Object, tag string) *jsonx.Object {
	if c.Fallback == nil || tag != "proxy" {
		rule.Set("outboundTag", tag)
		return rule
	}
	rule.Set("balancerTag", "tunnel")
	return rule
}

func xrayRouting(c *config.Config) *jsonx.Object {
	custom := func(position string) []any {
		var out []any
		for _, r := range c.Routes {
			if r.Position != position {
				continue
			}
			// A custom rule saying "proxy" means the tunnel too, and a fallback
			// that only covered generated rules would be a surprising kind of
			// half-measure.
			if c.Fallback != nil {
				if target, ok := r.Rule.GetString("outboundTag"); ok && target == "proxy" {
					r.Rule.Delete("outboundTag")
					r.Rule.Set("balancerTag", "tunnel")
				}
			}
			out = append(out, r.Rule)
		}
		return out
	}

	// Must come first: API traffic has to reach the API handler before any
	// other rule can claim it.
	rules := []any{
		obj("type", "field", "inboundTag", arr("api"), "outboundTag", "api"),
	}

	// Each upstream's probe inbound goes to that upstream and nowhere else.
	// Above every other rule on purpose: the point of the probe is to test one
	// server, so a geo split or a block rule claiming it would make the answer
	// describe the routing instead.
	for _, u := range c.Upstreams {
		rules = append(rules, obj("type", "field",
			"inboundTag", arr(upstreamInbound(u.Name)),
			"outboundTag", u.Outbound.Tag))
	}

	// Names that a profile sends through an upstream have to be RESOLVED
	// through it too. Xray's own DNS queries carry no client address, so the
	// profile rules below -- which all match on source -- never apply to them,
	// and the name is answered from the wrong side of the tunnel. For a network
	// that answers its own names differently, which is most of them, that means
	// the address is the outside view or nothing at all.
	for _, group := range dnsThroughUpstream(c) {
		// The resolver is reached THROUGH the upstream, not from here.
		//
		// This rule matches the query's destination, which is the only thing
		// that actually routes it: a DNS query leaving the resolver carries the
		// server's address, not the name being looked up, so a domain match
		// never sees it. Without this the box asks a corporate resolver over
		// the main tunnel -- from an address it does not serve, if it is
		// reachable at all -- and the answer is the outside view or nothing.
		if up := c.UpstreamByTag(group.tag); up != nil && up.DNS != "" {
			rules = append(rules, obj("type", "field",
				"inboundTag", arr(dnsTag),
				"ip", arr(up.DNS+"/32"),
				"outboundTag", group.tag))
		}
		// Kept as well: Xray matches sniffed names on some paths, and a DoH
		// resolver is a name rather than an address.
		rules = append(rules, obj("type", "field",
			"inboundTag", arr(dnsTag),
			"domain", strs(group.domains),
			"outboundTag", group.tag))
	}

	// position = "first": ahead of even the per-client policy rules. This is
	// where a hard block belongs — "never let anything reach this ip:port",
	// regardless of which device asked.
	rules = append(rules, custom("first")...)

	if len(c.BlockGeosite) > 0 {
		rules = append(rules, obj("type", "field",
			"domain", strs(c.BlockGeosite), "outboundTag", "block"))
	}
	if len(c.BlockGeoIP) > 0 {
		rules = append(rules, obj("type", "field",
			"ip", strs(c.BlockGeoIP), "outboundTag", "block"))
	}
	if c.BlockBittorrent {
		rules = append(rules, obj("type", "field",
			"protocol", arr("bittorrent"), "outboundTag", "block"))
	}

	if blocked := c.ClientsBy("block"); len(blocked) > 0 {
		rules = append(rules, obj("type", "field",
			"source", strs(blocked), "outboundTag", "block"))
	}

	// A "direct" client shouldn't reach Xray at all (nftables returns it before
	// TPROXY), but if one is added here without re-applying the firewall, this
	// keeps the intent correct rather than silently proxying it.
	if directClients := c.ClientsBy("direct"); len(directClients) > 0 {
		rules = append(rules, obj("type", "field",
			"source", strs(directClients), "outboundTag", "direct"))
	}

	// Profile exceptions come before the global geo split: "send
	// corp.example.ir through the work upstream" has to beat "all .ir goes
	// direct", because the per-device rule is the more specific statement.
	for _, p := range c.Profiles {
		sources := c.ProfileSources(p.Name)
		if len(sources) == 0 {
			continue
		}
		for _, route := range p.Routes {
			if len(route.Domains) > 0 {
				rules = append(rules, tunnelTarget(c, obj("type", "field",
					"source", strs(sources),
					"domain", strs(route.Domains)), route.Tag))
			}
			if len(route.IPs) > 0 {
				rules = append(rules, tunnelTarget(c, obj("type", "field",
					"source", strs(sources),
					"ip", strs(route.IPs)), route.Tag))
			}
		}
	}

	// The box resolving on a profile device's behalf.
	//
	// AdGuard answers the LAN, so its query to an upstream's resolver comes
	// from this box, not from the device that asked -- and every rule above
	// matches on the device. Without this the query falls to the geo split,
	// where geoip:private covers the resolver's own range, and it is sent
	// direct: out of the WAN, to an address only the upstream can reach.
	//
	// Narrow on purpose. Only this box, only that resolver, only port 53: the
	// resolver is reachable through the upstream alone, and widening the source
	// here would let any intercepted device reach it.
	if c.BoxIP != "" {
		for _, u := range c.Upstreams {
			if u.DNS == "" {
				continue
			}
			rules = append(rules, obj("type", "field",
				"source", arr(c.BoxIP),
				"ip", arr(u.DNS+"/32"),
				"port", "53",
				"outboundTag", u.Outbound.Tag))
		}
	}

	// position = "before" (the default): after per-client policy, ahead of the
	// global geo split — so a custom rule wins over "all .ir goes direct".
	rules = append(rules, custom("before")...)

	if len(c.DirectGeosite) > 0 {
		rules = append(rules, obj("type", "field",
			"domain", strs(c.DirectGeosite), "outboundTag", "direct"))
	}
	if len(c.DirectGeoIP) > 0 {
		rules = append(rules, obj("type", "field",
			"ip", strs(c.DirectGeoIP), "outboundTag", "direct"))
	}

	// position = "after": the geo split has already had its say; this catches
	// what it did not claim, before any of the fallthrough defaults.
	rules = append(rules, custom("after")...)

	// Then each profile's fallthrough. After the geo rules, so a profile client
	// still gets the domestic-direct split for everything its own rules did not
	// claim.
	for _, p := range c.Profiles {
		// base = "proxy" is what every unmatched flow already does, so a rule
		// saying it again only pins the device to a decision the catch-all
		// makes anyway — and reads, in the generated config, as if the profile
		// were treated differently from a plain proxy client. It is not.
		// base = "direct" does differ from the catch-all, so it stays.
		if p.Base == "proxy" {
			continue
		}
		if sources := c.ProfileSources(p.Name); len(sources) > 0 {
			rules = append(rules, tunnelTarget(c, obj("type", "field",
				"source", strs(sources)), p.Base))
		}
	}

	routing := obj("domainStrategy", c.DomainStrategy)
	// Reserve the position of "rules" before "balancers" is added, so the keys
	// come out in the order the config is normally read in. The final rule
	// depends on whether a balancer exists, so the value is filled in below.
	routing.Set("rules", nil)

	// The fallthrough. With a fallback configured this is the balancer, which
	// picks between proxy and fallback by observed latency; without one it is
	// the tunnel outright.
	if c.Fallback != nil {
		routing.Set("balancers", arrAny(obj(
			"tag", "tunnel",
			"selector", arr("proxy", "fallback"),
			"strategy", obj("type", "leastPing"),
		)))
		rules = append(rules, obj("type", "field",
			"network", "tcp,udp", "balancerTag", "tunnel"))
	} else {
		rules = append(rules, obj("type", "field",
			"network", "tcp,udp", "outboundTag", "proxy"))
	}
	routing.Set("rules", rules)
	return routing
}

// --------------------------------------------------------------- utilities --

// obj builds an ordered object from alternating key/value arguments.
func obj(kv ...any) *jsonx.Object {
	o := jsonx.NewObject()
	for i := 0; i+1 < len(kv); i += 2 {
		o.Set(kv[i].(string), kv[i+1])
	}
	return o
}

func arr(items ...string) []any { return strs(items) }

func arrAny(items ...any) []any { return items }

// strs converts to []any so an empty list marshals as [] rather than null.
func strs(items []string) []any {
	out := make([]any, 0, len(items))
	for _, s := range items {
		out = append(out, s)
	}
	return out
}

// num renders an integer as a JSON number without going through float64.
func num(n int) json.Number { return json.Number(strconv.Itoa(n)) }

func isIP(value string) bool {
	_, err := netip.ParseAddr(value)
	return err == nil
}
