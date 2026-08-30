// Package config loads, validates and normalises gateway.toml.
//
// gateway.toml is the single source of truth: everything the gateway installs
// is derived from it, so a rebuilt box comes back from one file. That makes
// validation load-bearing — a config that is merely accepted here and wrong
// later takes the LAN offline, so this package prefers a loud error at load
// time over any form of silent default.
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/am1nr/gateway/internal/jsonx"
)

// nameRE constrains profile, upstream and job names. They become Xray outbound
// tags and cron filenames, so keep them boring.
var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,23}$`)

var userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`)

// Load reads and validates gateway.toml.
func Load(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, errf("%s not found. Copy gateway.example.toml to gateway.toml, "+
			"or run `gw init`.", path)
	}
	var raw map[string]any
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, errf("%s: %v", path, err)
	}
	return newConfig(raw, routeKeyOrder(md), path)
}

// routeKeyOrder recovers the key order of every [[route]] table.
//
// A custom route's TOML table IS the Xray rule, so the keys are the user's
// words. toml.MetaData.Keys() reports them in document order, with a bare
// "route" marking the start of each array element.
func routeKeyOrder(md toml.MetaData) [][]string {
	var out [][]string
	for _, key := range md.Keys() {
		parts := []string(key)
		if len(parts) == 0 || parts[0] != "route" {
			continue
		}
		if len(parts) == 1 {
			out = append(out, nil)
			continue
		}
		if len(out) == 0 {
			continue
		}
		// Only direct children; a nested table's keys are sorted instead.
		if len(parts) == 2 {
			out[len(out)-1] = append(out[len(out)-1], parts[1])
		}
	}
	return out
}

// New validates an already-decoded gateway.toml. Key order for custom routing
// rules is not recoverable this way, so those keys are sorted.
func New(raw map[string]any, path string) (*Config, error) {
	return newConfig(raw, nil, path)
}

func newConfig(raw map[string]any, routeOrder [][]string, path string) (*Config, error) {
	c := &Config{
		routeKeyOrder:  routeOrder,
		Raw:            raw,
		Path:           path,
		Intercepted:    map[string]bool{},
		RouteTargets:   map[string]string{},
		upstreamByName: map[string]*Upstream{},
		profileByName:  map[string]*Profile{},
	}
	for _, section := range []func(map[string]any) error{
		c.parseNet,
		c.parseXray,
		c.parseRouting,
		c.parseGeodata,
		c.parseBootstrap,
		c.parseDNS,
		c.parseUpstreams,
		c.parseProfiles,
		c.parseCustomRoutes,
		c.parseClients,
		c.parseTailscale,
		c.parseWeb,
		c.finishTailscale,
		c.parseJobs,
		c.parseHealth,
		c.parseSystem,
	} {
		if err := section(raw); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// ------------------------------------------------------------------- net --

func (c *Config) parseNet(raw map[string]any) error {
	if _, err := need(raw, "net", "root"); err != nil {
		return err
	}
	net := table(raw, "net")

	var err error
	if c.WANIf, err = needString(net, "wan_if", "net"); err != nil {
		return err
	}
	lanCidr, err := needString(net, "lan_cidr", "net")
	if err != nil {
		return err
	}
	if c.LAN, err = parsePrefix(lanCidr, "net.lan_cidr"); err != nil {
		return err
	}
	c.LANCidr = c.LAN.String()

	routerStr, err := needString(net, "router", "net")
	if err != nil {
		return err
	}
	router, err := parseAddr(routerStr, "net.router")
	if err != nil {
		return err
	}
	c.Router = routerStr

	boxStr, err := needString(net, "static_ip", "net")
	if err != nil {
		return err
	}
	box, err := parseAddr(boxStr, "net.static_ip")
	if err != nil {
		return err
	}
	c.BoxIP = boxStr

	if c.PrefixLen, err = integer(net, "prefix_len", c.LAN.Bits()); err != nil {
		return err
	}

	for _, pair := range []struct {
		label string
		addr  netip.Addr
		text  string
	}{{"router", router, c.Router}, {"static_ip", box, c.BoxIP}} {
		if !c.LAN.Contains(pair.addr) {
			return errf("net.%s (%s) is not inside net.lan_cidr (%s)",
				pair.label, pair.text, c.LANCidr)
		}
	}
	if c.Router == c.BoxIP {
		return errf("net.router and net.static_ip cannot be the same address")
	}

	c.IPv6Mode = str(table(raw, "ipv6"), "mode", "off")
	if c.IPv6Mode != "off" && c.IPv6Mode != "pass" {
		return errf("ipv6.mode must be 'off' or 'pass'")
	}
	return nil
}

// ------------------------------------------------------------------ xray --

func (c *Config) parseXray(raw map[string]any) error {
	if _, err := need(raw, "xray", "root"); err != nil {
		return err
	}
	xr := table(raw, "xray")

	var err error
	if c.TproxyPort, err = integer(xr, "tproxy_port", 12345); err != nil {
		return err
	}
	if c.SocksPort, err = integer(xr, "socks_port", 10808); err != nil {
		return err
	}
	if c.HTTPPort, err = integer(xr, "http_port", 10809); err != nil {
		return err
	}
	// Loopback stats API. Makes "did this flow go direct or through the
	// tunnel?" answerable exactly, instead of by inference.
	if c.APIPort, err = integer(xr, "api_port", 10085); err != nil {
		return err
	}
	c.LogLevel = str(xr, "log_level", "warning")
	c.DomainStrategy = str(xr, "domain_strategy", "IPIfNonMatch")
	if c.OutboundMark, err = integer(xr, "outbound_mark", 255); err != nil {
		return err
	}

	// Performance is parsed before outbounds, which consume it.
	perf := table(raw, "performance")
	// Xray's per-connection buffer, in KB. Left unset by default: shrinking it
	// caps throughput on a high-latency path (the window has to hold a
	// bandwidth-delay product, and a censored route is usually long), and
	// picking a number without measuring the specific link is how you make
	// things slower while believing you tuned them. -1 means "leave Xray's own
	// default alone".
	if c.BufferSizeKB, err = integer(perf, "buffer_size_kb", -1); err != nil {
		return err
	}
	// Applied to outbound sockets. BBR helps most on a lossy path, which is
	// what a censored route usually is.
	c.TCPCongestion = str(perf, "tcp_congestion", "bbr")
	if c.TCPNoDelay, err = boolean(perf, "tcp_no_delay", true); err != nil {
		return err
	}
	if c.ConnIdle, err = integer(perf, "conn_idle_sec", 300); err != nil {
		return err
	}

	outboundSpec, err := need(xr, "outbound", "xray")
	if err != nil {
		return err
	}
	spec, ok := outboundSpec.(map[string]any)
	if !ok {
		return errf("[xray.outbound] must be a table")
	}
	if c.Server, err = c.loadOutbound(spec, "xray.outbound", "proxy"); err != nil {
		return err
	}

	fb := table(xr, "fallback")
	enabled, err := boolean(fb, "enabled", false)
	if err != nil {
		return err
	}
	if enabled {
		if c.Fallback, err = c.loadOutbound(fb, "xray.fallback", "fallback"); err != nil {
			return err
		}
	}
	return nil
}

// --------------------------------------------------------------- routing --

func (c *Config) parseRouting(raw map[string]any) error {
	rt := table(raw, "routing")

	var err error
	if c.DirectGeosite, err = stringList(rt, "direct_geosite", []string{"geosite:private"}); err != nil {
		return err
	}
	if c.DirectGeoIP, err = stringList(rt, "direct_geoip", []string{"geoip:private"}); err != nil {
		return err
	}
	if c.BlockGeosite, err = stringList(rt, "block_geosite", nil); err != nil {
		return err
	}
	if c.BlockGeoIP, err = stringList(rt, "block_geoip", nil); err != nil {
		return err
	}
	if c.BlockBittorrent, err = boolean(rt, "block_bittorrent", false); err != nil {
		return err
	}

	// Private ranges that are genuinely reachable here, beyond this LAN.
	// Everything else in RFC1918 arriving from a client is treated as a
	// poisoned DNS answer rather than quietly bypassed — see the ruleset.
	extra, err := stringList(rt, "extra_local_networks", nil)
	if err != nil {
		return err
	}
	var extraPrefixes []netip.Prefix
	for _, cidr := range extra {
		p, err := parsePrefix(cidr, "routing.extra_local_networks")
		if err != nil {
			return err
		}
		extraPrefixes = append(extraPrefixes, p)
	}
	// Two overlapping entries here would be rejected by nftables as
	// conflicting intervals, and the whole ruleset would fail to load over
	// what is really a redundant line in the config.
	c.ExtraLocal = collapsePrefixes(extraPrefixes)
	if c.DropPrivate, err = boolean(rt, "drop_private_destinations", true); err != nil {
		return err
	}
	return nil
}

// --------------------------------------------------------------- geodata --

func (c *Config) parseGeodata(raw map[string]any) error {
	geo := table(raw, "geodata")

	var err error
	// A truncated .dat takes the tunnel down, and this runs unattended.
	if c.GeoMinBytes, err = integer(geo, "min_bytes", 102400); err != nil {
		return err
	}

	sources, err := tables(geo, "source")
	if err != nil {
		return err
	}

	for i, raw := range sources {
		where := fmt.Sprintf("geodata.source[%d]", i)
		source, err := parseGeoSource(raw, where)
		if err != nil {
			return err
		}
		c.GeoSources = append(c.GeoSources, source)
	}

	// A config written before multiple sources existed sets repo, files and
	// url_template directly on [geodata]. Those keep working as a single
	// source: an existing gateway must not need its config edited to keep
	// updating its routing data.
	if len(c.GeoSources) == 0 {
		legacy, err := parseGeoSource(geo, "geodata")
		if err != nil {
			return err
		}
		c.GeoSources = []GeoSource{legacy}
	}

	enabled := 0
	for _, s := range c.GeoSources {
		if s.Enabled {
			enabled++
		}
	}
	if enabled == 0 {
		return errf("every geodata source is disabled, so nothing would keep the " +
			"routing data current. Enable one, or remove them all to use the default.")
	}
	return nil
}

// defaultGeoRepo is where routing data comes from unless told otherwise.
const defaultGeoRepo = "Chocolate4U/Iran-v2ray-rules"

// defaultGeoURL is the template used when files are pinned and no other is set.
const defaultGeoURL = "https://github.com/Chocolate4U/Iran-v2ray-rules/releases/latest/download/{0}.dat"

// parseGeoSource reads one source, from either [[geodata.source]] or the
// flat [geodata] form.
func parseGeoSource(raw map[string]any, where string) (GeoSource, error) {
	var s GeoSource
	var err error

	s.Repo = strings.Trim(str(raw, "repo", ""), "/")
	// Only the flat legacy form gets the default repo. A [[geodata.source]]
	// that names neither a repo nor a template is a mistake, and silently
	// substituting somebody else's rules for it would be a bad way to find out.
	if where == "geodata" && s.Repo == "" && raw["repo"] == nil {
		s.Repo = defaultGeoRepo
	}
	if s.Repo != "" && strings.Count(s.Repo, "/") != 1 {
		return s, errf("%s.repo %q must be owner/name, e.g. %q", where, s.Repo, defaultGeoRepo)
	}

	s.URLTemplate = str(raw, "url_template", "")
	if s.URLTemplate == "" && where == "geodata" {
		s.URLTemplate = defaultGeoURL
	}
	if s.URLTemplate != "" && !strings.Contains(s.URLTemplate, "{0}") {
		return s, errf("%s.url_template must contain {0}, which is replaced with "+
			"each file name (geoip, geosite)", where)
	}

	if s.Files, err = stringList(raw, "files", nil); err != nil {
		return s, err
	}
	if s.Enabled, err = boolean(raw, "enabled", true); err != nil {
		return s, err
	}

	// Release discovery needs a repo; a pinned set needs somewhere to fetch
	// from. One of the two has to be true.
	switch {
	case len(s.Files) == 0 && s.Repo == "":
		return s, errf("%s needs either `repo` (download every .dat in the latest "+
			"release) or a non-empty `files` list to use with url_template", where)
	case len(s.Files) > 0 && s.URLTemplate == "" && s.Repo == "":
		return s, errf("%s pins `files` but has no url_template or repo to fetch "+
			"them from", where)
	}

	s.Name = str(raw, "name", "")
	if s.Name == "" {
		s.Name = s.Repo
	}
	if s.Name == "" {
		s.Name = s.URLTemplate
	}
	return s, nil
}

// ------------------------------------------------------- bootstrap proxy --

func (c *Config) parseBootstrap(raw map[string]any) error {
	// Only for jobs that need the internet BEFORE the tunnel exists: installing
	// Xray, fetching geodata, apt. Once the gateway is running its own traffic
	// is already proxied and this is unused.
	boot := table(raw, "bootstrap")
	c.BootstrapProxy = strings.TrimSpace(str(boot, "socks_proxy", ""))
	if c.BootstrapProxy == "" {
		return nil
	}
	schemes := []string{"socks5://", "socks5h://", "socks4://", "http://", "https://"}
	for _, s := range schemes {
		if strings.HasPrefix(c.BootstrapProxy, s) {
			return nil
		}
	}
	return errf("bootstrap.socks_proxy %q needs a scheme, one of: %s. Prefer "+
		"socks5h:// so DNS is resolved at the proxy rather than locally.",
		c.BootstrapProxy, strings.Join(schemes, ", "))
}

// ------------------------------------------------------------------- dns --

func (c *Config) parseDNS(raw map[string]any) error {
	dns := table(raw, "dns")

	var err error
	if c.DNSPort, err = integer(dns, "adguard_port", 53); err != nil {
		return err
	}
	if c.UIPort, err = integer(dns, "adguard_ui_port", 3000); err != nil {
		return err
	}
	if c.UpProxied, err = stringList(dns, "upstreams_proxied", []string{"https://1.1.1.1/dns-query"}); err != nil {
		return err
	}
	if c.UpDirect, err = stringList(dns, "upstreams_direct", []string{"1.1.1.1"}); err != nil {
		return err
	}
	if c.DirectSuffixes, err = stringList(dns, "direct_suffixes", []string{"ir"}); err != nil {
		return err
	}
	if c.Bootstrap, err = stringList(dns, "bootstrap", []string{"1.1.1.1"}); err != nil {
		return err
	}
	// Redirect plain DNS from LAN clients to AdGuard, whatever they are
	// configured to use. Only catches queries that actually traverse this box:
	// a client pointed at the router resolves over the local segment and never
	// reaches us.
	if c.DNSIntercept, err = boolean(dns, "intercept", true); err != nil {
		return err
	}
	if c.Blocklists, err = stringList(dns, "blocklists", nil); err != nil {
		return err
	}
	if c.QuerylogDays, err = integer(dns, "querylog_days", 3); err != nil {
		return err
	}
	if c.StatslogDays, err = integer(dns, "statslog_days", 7); err != nil {
		return err
	}
	// AdGuard's own admin interface. Its port was previously opened to the LAN
	// by a hardcoded rule, with no way to narrow, widen or close it.
	//
	// ui_enabled mirrors web.enabled: it is how you say "not reachable over the
	// network at all". ui_allow_cidrs narrows it, the same way and with the same
	// empty-means-default rule as the dashboard's.
	if c.UIEnabled, err = boolean(dns, "ui_enabled", true); err != nil {
		return err
	}
	c.UIAllow, err = allowList(dns, "ui_allow_cidrs", "dns.ui_allow_cidrs",
		"AdGuard's admin interface", []string{c.LANCidr})
	if err != nil {
		return err
	}
	if !c.UIEnabled {
		c.UIAllow = nil
	}

	for _, u := range c.UpProxied {
		if !strings.HasPrefix(u, "https://") {
			continue
		}
		hostpart := strings.SplitN(strings.TrimPrefix(u, "https://"), "/", 2)[0]
		hostpart = strings.SplitN(hostpart, ":", 2)[0]
		if _, err := netip.ParseAddr(hostpart); err != nil {
			return errf("dns.upstreams_proxied: %q uses a hostname. Use an IP "+
				"literal (https://1.1.1.1/dns-query) — a hostname here needs "+
				"DNS to resolve the DNS server, which cannot work at boot.", u)
		}
	}
	return nil
}

// ------------------------------------------------------------- upstreams --

func (c *Config) parseUpstreams(raw map[string]any) error {
	entries, err := tables(raw, "upstream")
	if err != nil {
		return err
	}
	for i, u := range entries {
		where := fmt.Sprintf("upstream[%d]", i)
		if err := checkKeys(u, where,
			[]string{"name", "file", "json", "server_ip", "server_domain",
				"location", "dns"}, misplaced); err != nil {
			return err
		}
		name := str(u, "name", "")
		if !nameRE.MatchString(name) {
			return errf("%s.name %q must be 1-24 chars of lowercase "+
				"letters, digits or dashes", where, name)
		}
		if _, dup := c.upstreamByName[name]; dup {
			return errf("%s: duplicate upstream name %q", where, name)
		}
		if isBuiltin(name) {
			return errf("%s.name %q is reserved — it is a built-in route target", where, name)
		}
		ob, err := c.loadOutbound(u, where, "up-"+name)
		if err != nil {
			return err
		}
		location := str(u, "location", "outside")
		if location != "inside" && location != "outside" {
			return errf("%s.location is %q — it must be \"inside\" (in the country) "+
				"or \"outside\"", where, location)
		}
		resolver := str(u, "dns", "")
		if resolver != "" && !isIPLiteral(resolver) {
			return errf("%s.dns must be an IP address, not %q — resolving the "+
				"resolver would need the DNS this is meant to provide",
				where, resolver)
		}
		// One loopback port per upstream, so each can be probed on its own.
		// Numbered from the SOCKS port so they move together and a box with an
		// unusual port layout does not collide.
		up := &Upstream{
			Name:      name,
			Outbound:  ob,
			Location:  location,
			DNS:       resolver,
			ProbePort: c.SocksPort + 100 + len(c.Upstreams),
		}
		c.Upstreams = append(c.Upstreams, up)
		c.upstreamByName[name] = up
	}

	// Where a profile rule may send traffic.
	for _, up := range c.Upstreams {
		c.RouteTargets[up.Name] = up.Outbound.Tag
	}
	for _, p := range BuiltinPolicies {
		c.RouteTargets[p] = p
	}
	return nil
}

// -------------------------------------------------------------- profiles --

func (c *Config) parseProfiles(raw map[string]any) error {
	entries, err := tables(raw, "profile")
	if err != nil {
		return err
	}
	for i, pr := range entries {
		where := fmt.Sprintf("profile[%d]", i)
		if err := checkKeys(pr, where,
			[]string{"name", "base", "route"}, misplaced); err != nil {
			return err
		}
		name := str(pr, "name", "")
		if !nameRE.MatchString(name) {
			return errf("%s.name %q must be 1-24 chars of lowercase "+
				"letters, digits or dashes", where, name)
		}
		if isBuiltin(name) {
			return errf("%s.name %q is a built-in policy name", where, name)
		}
		if _, clash := c.upstreamByName[name]; clash {
			return errf("%s.name %q is already an upstream name — "+
				"profiles and upstreams share a namespace", where, name)
		}
		if _, dup := c.profileByName[name]; dup {
			return errf("%s: duplicate profile name %q", where, name)
		}

		base := str(pr, "base", "proxy")
		if base != "proxy" && base != "direct" {
			return errf("%s.base must be 'proxy' or 'direct' (got %q). "+
				"A profile that blocked everything would have nothing to route.",
				where, base)
		}

		routeTables, err := tables(pr, "route")
		if err != nil {
			return err
		}
		var routes []ProfileRoute
		for j, r := range routeTables {
			rwhere := fmt.Sprintf("%s.route[%d]", where, j)
			if err := checkKeys(r, rwhere,
				[]string{"via", "domains", "ips"}, misplaced); err != nil {
				return err
			}
			via := str(r, "via", "")
			tag, known := c.RouteTargets[via]
			if !known {
				return errf("%s.via %q is not a known target. Expected one of: %s",
					rwhere, via, strings.Join(sortedKeys(c.RouteTargets), ", "))
			}
			domains, err := stringList(r, "domains", nil)
			if err != nil {
				return err
			}
			ips, err := stringList(r, "ips", nil)
			if err != nil {
				return err
			}
			if len(domains) == 0 && len(ips) == 0 {
				return errf("%s matches nothing — give it `domains`, `ips`, or both", rwhere)
			}
			for _, cidr := range ips {
				if strings.HasPrefix(cidr, "geoip:") {
					continue
				}
				if _, err := parsePrefix(cidr, rwhere+".ips"); err != nil {
					return err
				}
			}
			routes = append(routes, ProfileRoute{Via: via, Tag: tag, Domains: domains, IPs: ips})
		}
		if len(routes) == 0 {
			return errf("%s has no [[profile.route]] rules, so it is just "+
				"policy = %q. Use the built-in policy instead.", where, base)
		}

		p := &Profile{Name: name, Base: base, Routes: routes}
		c.Profiles = append(c.Profiles, p)
		c.profileByName[name] = p
	}

	c.Policies = append(append([]string(nil), BuiltinPolicies...), profileNames(c.Profiles)...)
	// Every profile needs its traffic in front of Xray to be split at all.
	c.Intercepted["proxy"] = true
	for _, p := range c.Profiles {
		c.Intercepted[p.Name] = true
	}
	return nil
}

// --------------------------------------------------------- custom routes --

// routeMatchers are the Xray rule keys that actually select traffic. A rule
// with none of them matches nothing, which Xray accepts and silently ignores.
var routeMatchers = []string{"domain", "ip", "port", "sourcePort", "network",
	"source", "user", "inboundTag", "protocol", "attrs"}

func (c *Config) parseCustomRoutes(raw map[string]any) error {
	entries, err := tables(raw, "route")
	if err != nil {
		return err
	}
	for i, r := range entries {
		where := fmt.Sprintf("route[%d]", i)
		position := str(r, "position", "before")
		if position != "first" && position != "before" && position != "after" {
			return errf("%s.position must be 'first' (before every other rule), "+
				"'before' (before the geo split, the default) or 'after' "+
				"(after the geo split)", where)
		}

		var rule *jsonx.Object
		if rawJSON, ok := r["json"]; ok {
			// A raw rule, for anything the TOML form cannot express. Its key
			// order comes from the JSON text.
			text, ok := rawJSON.(string)
			if !ok {
				return errf("%s.json must be a string containing one rule object", where)
			}
			rule, err = jsonx.DecodeObject([]byte(text))
			if err != nil {
				return errf("%s.json: not valid JSON — %v", where, err)
			}
		} else {
			// The TOML table IS the rule, minus the one key the gateway
			// consumes. Keys keep the order they were written in.
			rule = jsonx.NewObject()
			for _, k := range c.routeKeys(i, r) {
				if k == "position" {
					continue
				}
				rule.Set(k, tomlToJSON(r[k]))
			}
		}

		rule.SetDefault("type", "field")
		if !rule.Has("balancerTag") {
			target, _ := rule.GetString("outboundTag")
			if target == "" {
				return errf("%s has no outboundTag — say where the matched "+
					"traffic should go (one of: %s)", where,
					strings.Join(sortedKeys(c.RouteTargets), ", "))
			}
			if tag, ok := c.RouteTargets[target]; ok {
				rule.Set("outboundTag", tag)
			} else if !isRouteTag(c.RouteTargets, target) {
				return errf("%s.outboundTag %q is not a known target. Expected one of: %s",
					where, target, strings.Join(sortedKeys(c.RouteTargets), ", "))
			}
		}

		matched := false
		for _, m := range routeMatchers {
			if rule.Has(m) {
				matched = true
				break
			}
		}
		if !matched {
			return errf("%s matches nothing — add at least one of: %s",
				where, strings.Join(routeMatchers, ", "))
		}
		c.Routes = append(c.Routes, CustomRoute{Position: position, Rule: rule})
	}
	return nil
}

// routeKeys returns the keys of route i in the order they were written, or
// sorted when that order was not recorded. Any key present in the table but
// missing from the recorded order is appended, so a key can never be dropped.
func (c *Config) routeKeys(i int, r map[string]any) []string {
	if i >= len(c.routeKeyOrder) || len(c.routeKeyOrder[i]) == 0 {
		return sortedMapKeys(r)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(r))
	for _, k := range c.routeKeyOrder[i] {
		if _, ok := r[k]; ok && !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, k := range sortedMapKeys(r) {
		if !seen[k] {
			out = append(out, k)
		}
	}
	return out
}

// --------------------------------------------------------------- clients --

func (c *Config) parseClients(raw map[string]any) error {
	// A bare `default_policy = ...` written after any [table] is parsed as a
	// key of THAT table, so it silently does nothing. That is exactly what
	// happened in the first version of the example config, and the bug was
	// invisible because the ignored value matched the fallback. Reject it
	// loudly rather than quietly using the wrong policy.
	//
	// Sorted so the reported table is the same one every run.
	for _, name := range sortedMapKeys(raw) {
		if name == "policy" {
			continue
		}
		t, ok := raw[name].(map[string]any)
		if !ok {
			continue
		}
		if _, found := t["default_policy"]; found {
			return errf("default_policy is inside [%s], where TOML makes it "+
				"%s.default_policy and nothing reads it. Move it to:\n"+
				"\n  [policy]\n  default = \"proxy\"\n", name, name)
		}
	}

	fallback := str(raw, "default_policy", "proxy")
	c.DefaultPolicy = str(table(raw, "policy"), "default", fallback)
	if !contains(c.Policies, c.DefaultPolicy) {
		return errf("policy.default must be one of %s, not %q",
			strings.Join(c.Policies, ", "), c.DefaultPolicy)
	}

	entries, err := tables(raw, "client")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, cl := range entries {
		where := fmt.Sprintf("client[%d]", i)
		ipStr, err := needString(cl, "ip", where)
		if err != nil {
			return err
		}
		addr, err := parseAddr(ipStr, where+".ip")
		if err != nil {
			return err
		}
		policy := str(cl, "policy", c.DefaultPolicy)
		if !contains(c.Policies, policy) {
			return errf("%s.policy %q is not defined. Known policies: %s",
				where, policy, strings.Join(c.Policies, ", "))
		}
		if seen[ipStr] {
			return errf("%s: duplicate client ip %s", where, ipStr)
		}
		if !c.LAN.Contains(addr) {
			return errf("%s: %s is not inside net.lan_cidr", where, ipStr)
		}
		if ipStr == c.BoxIP || ipStr == c.Router {
			return errf("%s: %s is the gateway or the router itself", where, ipStr)
		}
		seen[ipStr] = true
		c.Clients = append(c.Clients, Client{
			IP: ipStr, Name: str(cl, "name", ipStr), Policy: policy,
		})
	}
	return nil
}

// ------------------------------------------------------------- tailscale --

func (c *Config) parseTailscale(raw map[string]any) error {
	ts := table(raw, "tailscale")

	var err error
	if c.TSEnabled, err = boolean(ts, "enabled", true); err != nil {
		return err
	}
	if c.TSSSH, err = boolean(ts, "ssh", true); err != nil {
		return err
	}
	if c.TSExitNode, err = boolean(ts, "exit_node", true); err != nil {
		return err
	}
	if c.TSSubnetRouter, err = boolean(ts, "subnet_router", true); err != nil {
		return err
	}
	// Which policy exit-node traffic gets. Any built-in policy or profile name,
	// so a remote device exiting through this box can be routed exactly like a
	// LAN client — including through a profile's upstreams. Validated in
	// finishTailscale, once the web section has had its say, to keep error
	// precedence identical to the original.
	legacy := "proxy"
	proxyEgress, err := boolean(ts, "proxy_tailnet_egress", true)
	if err != nil {
		return err
	}
	if !proxyEgress {
		legacy = "direct" // back-compat with the old boolean
	}
	c.TSExitPolicy = str(ts, "exit_node_policy", legacy)
	if c.TSRouteControl, err = boolean(ts, "route_control_via_xray", true); err != nil {
		return err
	}
	if c.TSLifelineMin, err = integer(ts, "lifeline_after_min", 10); err != nil {
		return err
	}
	return nil
}

func (c *Config) finishTailscale(raw map[string]any) error {
	if !contains(c.Policies, c.TSExitPolicy) {
		return errf("tailscale.exit_node_policy %q is not a known policy. "+
			"Expected one of: %s", c.TSExitPolicy, strings.Join(c.Policies, ", "))
	}
	return nil
}

// ------------------------------------------------------------------- web --

func (c *Config) parseWeb(raw map[string]any) error {
	w := table(raw, "web")

	var err error
	if c.WebEnabled, err = boolean(w, "enabled", true); err != nil {
		return err
	}
	c.WebListen = str(w, "listen", "0.0.0.0")
	if c.WebPort, err = integer(w, "port", 8088); err != nil {
		return err
	}
	if c.WebPort < 1 || c.WebPort > 65535 {
		return errf("web.port %d is out of range", c.WebPort)
	}
	for _, taken := range []int{c.DNSPort, c.UIPort, c.TproxyPort, c.SocksPort, c.HTTPPort, c.APIPort} {
		if c.WebPort == taken {
			return errf("web.port %d collides with another gateway service", c.WebPort)
		}
	}
	if c.WebTLS, err = boolean(w, "tls", true); err != nil {
		return err
	}
	c.WebCert = str(w, "cert", "/etc/gateway/web.crt")
	c.WebKey = str(w, "key", "/etc/gateway/web.key")
	if c.WebTLS && (c.WebCert == "" || c.WebKey == "") {
		return errf("web.tls is on but web.cert/web.key are not set")
	}

	// Default to the LAN plus the tailnet: the dashboard can rewrite the
	// firewall, so it is never reachable from anywhere by accident.
	//
	// An explicitly empty list is honoured as "from nowhere" rather than
	// silently replaced by the default. "Reachable from no network" is a
	// legitimate thing to want — the dashboard is then only reachable by
	// forwarding a port over SSH — and a setting that quietly does the opposite
	// of what it says is worse than one that refuses.
	c.WebAllow, err = allowList(w, "allow_cidrs", "web.allow_cidrs",
		"the dashboard", []string{c.LANCidr, TailnetV4})
	if err != nil {
		return err
	}

	if c.SessionHours, err = integer(w, "session_hours", 12); err != nil {
		return err
	}
	if c.MaxFailedLogins, err = integer(w, "max_failed_logins", 5); err != nil {
		return err
	}
	if c.LockoutMinutes, err = integer(w, "lockout_minutes", 15); err != nil {
		return err
	}
	return nil
}

// ------------------------------------------------------------------ jobs --

func (c *Config) parseJobs(raw map[string]any) error {
	entries, err := tables(raw, "job")
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for i, j := range entries {
		where := fmt.Sprintf("job[%d]", i)
		name := str(j, "name", "")
		if !nameRE.MatchString(name) {
			return errf("%s.name %q must be 1-24 chars of lowercase "+
				"letters, digits or dashes", where, name)
		}
		if seen[name] {
			return errf("%s: duplicate job name %q", where, name)
		}
		seen[name] = true

		schedule := strings.TrimSpace(str(j, "schedule", ""))
		if err := validateCron(schedule, where); err != nil {
			return err
		}

		script := str(j, "script", "")
		if strings.TrimSpace(script) == "" {
			return errf("%s.script is empty — nothing to run", where)
		}

		user := str(j, "user", "root")
		if !userRE.MatchString(user) {
			return errf("%s.user %q is not a valid user name", where, user)
		}

		enabled, err := boolean(j, "enabled", true)
		if err != nil {
			return err
		}
		c.Jobs = append(c.Jobs, Job{
			Name:        name,
			Schedule:    schedule,
			Script:      script,
			User:        user,
			Enabled:     enabled,
			Description: str(j, "description", ""),
		})
	}
	return nil
}

// ---------------------------------------------------------------- health --

func (c *Config) parseHealth(raw map[string]any) error {
	h := table(raw, "health")

	var err error
	if c.HealthInterval, err = integer(h, "interval_sec", 30); err != nil {
		return err
	}
	c.ProbeURL = str(h, "probe_url", "https://www.gstatic.com/generate_204")
	if c.ProbeTimeout, err = integer(h, "probe_timeout_sec", 8); err != nil {
		return err
	}
	c.DomesticProbeURL = str(h, "domestic_probe_url", "https://www.irna.ir")
	if c.RestartAfter, err = integer(h, "restart_after_fails", 3); err != nil {
		return err
	}
	if c.FallbackAfter, err = integer(h, "fallback_after_fails", 6); err != nil {
		return err
	}
	if c.FallbackAfter < c.RestartAfter {
		return errf("health.fallback_after_fails must be >= health.restart_after_fails")
	}
	return nil
}

// ---------------------------------------------------------------- system --

func (c *Config) parseSystem(raw map[string]any) error {
	sy := table(raw, "system")

	var err error
	c.Timezone = str(sy, "timezone", "UTC")
	c.JournalMax = str(sy, "journal_max_use", "200M")
	if c.Zram, err = boolean(sy, "zram", true); err != nil {
		return err
	}
	if c.BBR, err = boolean(sy, "bbr", true); err != nil {
		return err
	}
	if c.Unattended, err = boolean(sy, "unattended_upgrades", true); err != nil {
		return err
	}

	// What the scheduled updater does, if anything. Geodata already has its own
	// daily timer; this covers the parts that otherwise never updated unless
	// somebody remembered to run `gw update` by hand.
	c.AutoUpdate = str(sy, "auto_update", "services")
	modes := []string{"off", "check", "services", "all"}
	if !contains(modes, c.AutoUpdate) {
		return errf("system.auto_update must be one of %s, not %q",
			strings.Join(modes, ", "), c.AutoUpdate)
	}
	c.AutoUpdateSchedule = str(sy, "auto_update_schedule", "weekly")
	if strings.TrimSpace(c.AutoUpdateSchedule) == "" {
		return errf("system.auto_update_schedule must not be empty")
	}
	if c.SSHAllowLAN, err = boolean(sy, "ssh_allow_lan", true); err != nil {
		return err
	}
	if c.SSHAllowTailnet, err = boolean(sy, "ssh_allow_tailnet", true); err != nil {
		return err
	}
	return nil
}

// allowList reads the networks that may reach a service.
//
// An empty list means the default, which is what gateway.example.toml has
// documented and shipped since the beginning: `allow_cidrs = []` in an existing
// config means "the LAN plus the tailnet", and reading it as "nowhere" would
// lock every existing install out of its own dashboard on the next apply.
//
// Narrowing is done by listing only what should reach it — a tailnet-only
// dashboard is `allow_cidrs = ["100.64.0.0/10"]`. Closing it entirely is what
// the service's own `enabled` flag is for.
func allowList(table map[string]any, key, where, what string, fallback []string) ([]string, error) {
	entries, err := stringList(table, key, nil)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return append([]string(nil), fallback...), nil
	}
	out := make([]string, 0, len(entries))
	for _, cidr := range entries {
		prefix, err := parsePrefix(cidr, where)
		if err != nil {
			return nil, err
		}
		if prefix.Bits() == 0 {
			return nil, errf("%s contains 0.0.0.0/0, which would expose %s to "+
				"everything the box can reach. List real networks.", where, what)
		}
		out = append(out, prefix.String())
	}
	return out, nil
}

// --------------------------------------------------------------- helpers --

func isBuiltin(name string) bool { return contains(BuiltinPolicies, name) }

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func isRouteTag(targets map[string]string, tag string) bool {
	for _, v := range targets {
		if v == tag {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func profileNames(profiles []*Profile) []string {
	out := make([]string, 0, len(profiles))
	for _, p := range profiles {
		out = append(out, p.Name)
	}
	return out
}

// AbsPath returns the config path as written, which is what the generated files
// quote back to the reader.
func (c *Config) AbsPath() string {
	if filepath.IsAbs(c.Path) {
		return c.Path
	}
	return c.Path
}

// checkKeys rejects a key this table does not understand.
//
// TOML has no schema, so a key written in the wrong table is not an error —
// it is simply never read, and the setting silently keeps its default. That
// failure mode is the worst kind here: `location` on a [[profile]] instead of
// its [[upstream]] leaves the upstream "outside" while the file plainly says
// inside, and nothing anywhere disagrees with you.
//
// belongsTo names the table a misplaced key would have worked in, so the
// message can say where to move it rather than only that it is wrong.
func checkKeys(t map[string]any, where string, allowed []string, belongsTo map[string]string) error {
	ok := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		ok[k] = true
	}
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if ok[k] {
			continue
		}
		if home, known := belongsTo[k]; known {
			return errf("%s.%s belongs in %s, not here. TOML does not object to a "+
				"key in the wrong table — it is simply never read, so the setting "+
				"keeps its default and nothing contradicts what the file says.",
				where, k, home)
		}
		return errf("%s.%s is not a setting this table has. Expected one of: %s",
			where, k, strings.Join(allowed, ", "))
	}
	return nil
}

// misplaced maps a key to the table it actually belongs in.
var misplaced = map[string]string{
	"location":  "[[upstream]]",
	"dns":       "[[upstream]] (or [dns] for the resolver settings)",
	"via":       "[[profile.route]]",
	"domains":   "[[profile.route]]",
	"ips":       "[[profile.route]]",
	"base":      "[[profile]]",
	"policy":    "[[client]]",
	"server_ip": "[xray.outbound], [xray.fallback] or [[upstream]]",
}
