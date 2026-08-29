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
	return []any{
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
}

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

func xrayRouting(c *config.Config) *jsonx.Object {
	custom := func(position string) []any {
		var out []any
		for _, r := range c.Routes {
			if r.Position == position {
				out = append(out, r.Rule)
			}
		}
		return out
	}

	// Must come first: API traffic has to reach the API handler before any
	// other rule can claim it.
	rules := []any{
		obj("type", "field", "inboundTag", arr("api"), "outboundTag", "api"),
	}

	// position = "first": ahead of even the per-client policy rules. This is
	// where a hard block belongs — "never let anything reach this ip:port",
	// regardless of which device asked.
	rules = append(rules, custom("first")...)

	if len(c.BlockGeosite) > 0 {
		rules = append(rules, obj("type", "field",
			"domain", strs(c.BlockGeosite), "outboundTag", "block"))
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
				rules = append(rules, obj("type", "field",
					"source", strs(sources),
					"domain", strs(route.Domains), "outboundTag", route.Tag))
			}
			if len(route.IPs) > 0 {
				rules = append(rules, obj("type", "field",
					"source", strs(sources),
					"ip", strs(route.IPs), "outboundTag", route.Tag))
			}
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
		if sources := c.ProfileSources(p.Name); len(sources) > 0 {
			rules = append(rules, obj("type", "field",
				"source", strs(sources), "outboundTag", p.Base))
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
