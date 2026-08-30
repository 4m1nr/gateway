package render

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/config"
	"github.com/am1nr/gateway/internal/jsonx"
)

// decodeRendered renders and re-parses, so assertions run against exactly the
// bytes Xray would be handed.
func decodeRendered(t *testing.T, cfg *config.Config) *jsonx.Object {
	t.Helper()
	raw, err := RenderXray(cfg)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	obj, err := jsonx.DecodeObject(raw)
	if err != nil {
		t.Fatalf("rendered config is not valid JSON: %v", err)
	}
	return obj
}

func rules(t *testing.T, conf *jsonx.Object) []*jsonx.Object {
	t.Helper()
	routing, ok := conf.GetObject("routing")
	if !ok {
		t.Fatal("no routing section")
	}
	arr, ok := routing.GetArray("rules")
	if !ok {
		t.Fatal("no routing.rules")
	}
	out := make([]*jsonx.Object, 0, len(arr))
	for _, r := range arr {
		o, ok := r.(*jsonx.Object)
		if !ok {
			t.Fatalf("routing rule is not an object: %T", r)
		}
		out = append(out, o)
	}
	return out
}

// Every outbound must carry the loop guard. An outbound without sockopt.mark
// makes Xray's own packets eligible for TPROXY, and the box deadlocks the
// moment interception is enabled. This is the highest-consequence check here.
func TestEveryOutboundIsTaggedAndMarked(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			cfg := loadFixture(t, name)
			conf := decodeRendered(t, cfg)
			outbounds, ok := conf.GetArray("outbounds")
			if !ok || len(outbounds) == 0 {
				t.Fatal("no outbounds")
			}
			for i, item := range outbounds {
				ob := item.(*jsonx.Object)
				tag, ok := ob.GetString("tag")
				if !ok || tag == "" {
					t.Errorf("outbound %d has no tag; routing rules reference outbounds by name", i)
					continue
				}
				proto, _ := ob.GetString("protocol")
				if proto == "blackhole" {
					// The block outbound never opens a socket, so it has
					// nothing to mark.
					continue
				}
				stream, ok := ob.GetObject("streamSettings")
				if !ok {
					t.Errorf("outbound %q has no streamSettings", tag)
					continue
				}
				sock, ok := stream.GetObject("sockopt")
				if !ok {
					t.Errorf("outbound %q has no sockopt — the loop guard is missing", tag)
					continue
				}
				mark, ok := sock.GetNumber("mark")
				if !ok {
					t.Errorf("outbound %q has no sockopt.mark — the loop guard is missing", tag)
					continue
				}
				if want := json.Number(itoa(cfg.OutboundMark)); mark != want {
					t.Errorf("outbound %q has mark %s, but the firewall exempts %s",
						tag, mark, want)
				}
			}
		})
	}
}

// API traffic has to reach the API handler before any other rule can claim it.
func TestAPIRuleComesFirst(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			rs := rules(t, decodeRendered(t, loadFixture(t, name)))
			if len(rs) == 0 {
				t.Fatal("no routing rules")
			}
			if tag, _ := rs[0].GetString("outboundTag"); tag != "api" {
				t.Errorf("first rule targets %q, want api — the stats API would be unreachable", tag)
			}
		})
	}
}

// Xray takes the first matching rule, so this ordering IS the behaviour: a
// profile's own exception must beat the global "all .ir goes direct" split, or
// the split silently wins and the profile does nothing.
func TestProfileExceptionsPrecedeTheGeoSplit(t *testing.T) {
	cfg := loadFixture(t, "profiles")
	rs := rules(t, decodeRendered(t, cfg))

	geoSplit := -1
	for i, r := range rs {
		if hasStringItem(r, "domain", "geosite:category-ir") {
			geoSplit = i
			break
		}
	}
	if geoSplit < 0 {
		t.Fatal("no domestic geosite rule found; the fixture no longer covers this")
	}

	for _, p := range cfg.Profiles {
		for _, route := range p.Routes {
			for _, d := range route.Domains {
				at := indexOfRuleWithDomain(rs, d)
				if at < 0 {
					t.Errorf("profile %q rule for %q is missing from the routing table", p.Name, d)
					continue
				}
				if at > geoSplit {
					t.Errorf("profile %q rule for %q is at %d, after the geo split at %d — "+
						"the split will claim it first and the profile will do nothing",
						p.Name, d, at, geoSplit)
				}
			}
		}
	}
}

// A profile's fallthrough must come AFTER the geo split, so a profile client
// still gets the domestic-direct split for everything its own rules did not
// claim.
func TestProfileFallthroughFollowsTheGeoSplit(t *testing.T) {
	cfg := loadFixture(t, "profiles")
	rs := rules(t, decodeRendered(t, cfg))

	lastGeo := -1
	for i, r := range rs {
		if hasStringItem(r, "domain", "geosite:category-ir") || hasStringItem(r, "ip", "geoip:ir") {
			lastGeo = i
		}
	}
	if lastGeo < 0 {
		t.Fatal("no geo split found; the fixture no longer covers this")
	}

	for _, p := range cfg.Profiles {
		// base = "proxy" emits no fallthrough: it would only repeat what the
		// catch-all already does, and the device is meant to behave like any
		// proxy client. Ordering against the geo split is still the question
		// here, but only for a base that actually produces a rule.
		if p.Base == "proxy" {
			continue
		}
		// The fallthrough is the rule whose source is exactly this profile's
		// source set and which matches nothing else. Matching on outboundTag
		// alone would also catch the per-client `direct` rule.
		want := cfg.ProfileSources(p.Name)
		at := -1
		for i, r := range rs {
			if r.Has("domain") || r.Has("ip") {
				continue
			}
			if sameStringSet(r, "source", want) {
				at = i
			}
		}
		if at < 0 {
			t.Errorf("profile %q has no fallthrough rule; traffic it does not "+
				"claim would fall through to the global default instead of %q",
				p.Name, p.Base)
			continue
		}
		if at < lastGeo {
			t.Errorf("profile %q fallthrough is at %d, before the geo split ends at %d — "+
				"its clients would lose the domestic-direct split", p.Name, at, lastGeo)
		}
		if tag, _ := rs[at].GetString("outboundTag"); tag != p.Base {
			t.Errorf("profile %q falls through to %q, want its base %q", p.Name, tag, p.Base)
		}
	}
}

// position = "first" lands ahead of everything, including per-client policy —
// which is what makes "nothing reaches this host, ever" true regardless of
// which device asked. "after" lands past the geo split. Misplacement produces
// no error, just a rule that quietly stops applying.
func TestCustomRoutePositions(t *testing.T) {
	cfg := loadFixture(t, "custom-routes")
	rs := rules(t, decodeRendered(t, cfg))

	firstGeo, lastGeo := -1, -1
	for i, r := range rs {
		if hasStringItem(r, "domain", "geosite:category-ir") || hasStringItem(r, "ip", "geoip:ir") {
			if firstGeo < 0 {
				firstGeo = i
			}
			lastGeo = i
		}
	}
	if firstGeo < 0 {
		t.Fatal("no geo split found; the fixture no longer covers this")
	}
	// Per-client policy rules are the block/direct source rules.
	firstPolicy := len(rs)
	for i, r := range rs {
		if r.Has("source") && !r.Has("domain") && !r.Has("ip") {
			if i < firstPolicy {
				firstPolicy = i
			}
		}
	}

	for _, route := range cfg.Routes {
		at := indexOfSameRule(rs, route.Rule)
		if at < 0 {
			t.Errorf("custom route %v never reached the routing table", route.Rule.Keys())
			continue
		}
		switch route.Position {
		case "first":
			if at > firstPolicy {
				t.Errorf(`position="first" rule landed at %d, after per-client policy at %d`, at, firstPolicy)
			}
		case "before":
			if at > firstGeo {
				t.Errorf(`position="before" rule landed at %d, after the geo split at %d — `+
					`"all .ir goes direct" will claim it first`, at, firstGeo)
			}
		case "after":
			if at < lastGeo {
				t.Errorf(`position="after" rule landed at %d, before the geo split ends at %d`, at, lastGeo)
			}
		}
	}
}

// A fallback turns the catch-all into a balancer. Without one it is the tunnel
// outright — but either way it must be last, or it swallows every rule below.
func TestCatchAllIsLast(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			cfg := loadFixture(t, name)
			conf := decodeRendered(t, cfg)
			rs := rules(t, conf)
			last := rs[len(rs)-1]
			if net, _ := last.GetString("network"); net != "tcp,udp" {
				t.Fatalf("last rule is not the catch-all: %v", last.Keys())
			}
			if cfg.Fallback != nil {
				if tag, _ := last.GetString("balancerTag"); tag != "tunnel" {
					t.Errorf("with a fallback configured the catch-all should use the balancer, got %v", last.Keys())
				}
				if _, ok := conf.GetObject("burstObservatory"); !ok {
					t.Error("a balancer without burstObservatory has nothing to measure latency with")
				}
			} else if tag, _ := last.GetString("outboundTag"); tag != "proxy" {
				t.Errorf("catch-all targets %q, want proxy", tag)
			}
		})
	}
}

// TPROXY hands Xray a destination IP and nothing else, so without sniffing no
// geosite rule can ever match and the domestic-direct split silently stops
// working.
func TestTproxyInboundSniffs(t *testing.T) {
	conf := decodeRendered(t, loadFixture(t, "default"))
	inbounds, _ := conf.GetArray("inbounds")
	for _, item := range inbounds {
		in := item.(*jsonx.Object)
		if tag, _ := in.GetString("tag"); tag != "tproxy-in" {
			continue
		}
		sniff, ok := in.GetObject("sniffing")
		if !ok {
			t.Fatal("tproxy inbound has no sniffing; geosite rules could never match")
		}
		if enabled, _ := sniff.Get("enabled"); enabled != true {
			t.Error("sniffing is present but disabled")
		}
		if !hasStringItem(sniff, "destOverride", "tls") {
			t.Error("sniffing does not cover TLS, which is most of the traffic")
		}
		return
	}
	t.Fatal("no tproxy-in inbound")
}

// Domestic DNS must not be trusted for non-domestic answers, and the DoH
// upstreams must never be reachable by name.
func TestDNSSplit(t *testing.T) {
	cfg := loadFixture(t, "default")
	conf := decodeRendered(t, cfg)
	dns, ok := conf.GetObject("dns")
	if !ok {
		t.Fatal("no dns section")
	}
	servers, _ := dns.GetArray("servers")
	sawDomestic := false
	for _, item := range servers {
		s, ok := item.(*jsonx.Object)
		if !ok {
			continue // a bare DoH URL string
		}
		if skip, _ := s.Get("skipFallback"); skip == true {
			sawDomestic = true
			if !s.Has("expectIPs") {
				t.Error("a domestic resolver has no expectIPs, so a lie about a " +
					"foreign name would be believed")
			}
		}
	}
	if !sawDomestic {
		t.Error("no domestic resolver entry found")
	}
}

// ---------------------------------------------------------------- helpers --

func hasStringItem(o *jsonx.Object, key, want string) bool {
	arr, ok := o.GetArray(key)
	if !ok {
		if s, ok := o.GetString(key); ok {
			return s == want
		}
		return false
	}
	for _, item := range arr {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}

// sameStringSet reports whether the rule's key holds exactly these strings.
func sameStringSet(o *jsonx.Object, key string, want []string) bool {
	arr, ok := o.GetArray(key)
	if !ok || len(arr) != len(want) {
		return false
	}
	for i, item := range arr {
		s, ok := item.(string)
		if !ok || s != want[i] {
			return false
		}
	}
	return true
}

func indexOfRuleWithDomain(rs []*jsonx.Object, domain string) int {
	for i, r := range rs {
		if hasStringItem(r, "domain", domain) {
			return i
		}
	}
	return -1
}

// indexOfSameRule finds a rendered rule by comparing its JSON to the parsed
// rule, which is the same object the renderer emits.
func indexOfSameRule(rs []*jsonx.Object, want *jsonx.Object) int {
	wantJSON, err := json.Marshal(want)
	if err != nil {
		return -1
	}
	for i, r := range rs {
		got, err := json.Marshal(r)
		if err == nil && string(got) == string(wantJSON) {
			return i
		}
	}
	return -1
}

// Everything that means "the tunnel" must fail over together.
//
// "proxy" names the primary outbound, but what a rule means by it is "through
// the tunnel" — and with a fallback configured the tunnel is the balancer. A
// rule pinned to the primary keeps using a dead server while everything else
// fails over, so a profile client loses connectivity at exactly the moment the
// failover existed to prevent that.
func TestEverythingThatMeansTheTunnelFailsOverTogether(t *testing.T) {
	cfg := loadFixture(t, "reality-fallback")
	t.Chdir(repoRoot(t))
	if cfg.Fallback == nil {
		t.Fatal("the fixture no longer configures a fallback")
	}

	rs := rules(t, decodeRendered(t, cfg))
	for i, r := range rs {
		tag, _ := r.GetString("outboundTag")
		if tag != "proxy" {
			continue
		}
		t.Errorf("rule %d still targets the primary outbound directly, so it "+
			"would not fail over: %v", i, r.Keys())
	}

	// And the balancer it points at has to exist, or every one of those rules
	// routes nowhere.
	routing, _ := decodeRendered(t, cfg).GetObject("routing")
	balancers, ok := routing.GetArray("balancers")
	if !ok || len(balancers) == 0 {
		t.Fatal("rules reference a balancer that is not declared")
	}
}

// A profile whose base is proxy is treated as a proxy client, not as a special
// case that happens to resolve the same way.
//
// It used to get a rule of its own saying "send this device to proxy" — which
// is what the catch-all already does for everyone. The rule changed nothing and
// read, in the generated config, as though the device were being handled
// differently. The device now falls through like any other proxy client, which
// also means it picks up the failover from the catch-all rather than needing
// its own copy of that decision.
func TestProfileWithProxyBaseIsNotPinned(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := configWithFallbackAndProfile(t)

	rs := rules(t, decodeRendered(t, cfg))
	for i, r := range rs {
		if !sameStringSet(r, "source", []string{"192.168.1.70"}) {
			continue
		}
		if r.Has("domain") || r.Has("ip") {
			continue // one of the profile's own exceptions, which is the point of it
		}
		t.Errorf("rule %d pins the device to a decision the catch-all already "+
			"makes: %v", i, r.Keys())
	}

	// And what it falls through to is the balancer, so it still fails over.
	last := rs[len(rs)-1]
	if tag, _ := last.GetString("balancerTag"); tag != "tunnel" {
		t.Errorf("the catch-all it now relies on is %v, not the balancer", last.Keys())
	}
}

// base = "direct" does differ from the catch-all, so that rule has to stay --
// without it the device would be proxied, which is the opposite of what the
// profile asks for.
func TestProfileWithDirectBaseKeepsItsRule(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := loadFixture(t, "profiles")

	var direct []string
	for _, p := range cfg.Profiles {
		if p.Base == "direct" {
			direct = cfg.ProfileSources(p.Name)
		}
	}
	if len(direct) == 0 {
		t.Skip("no direct-based profile in this fixture")
	}

	rs := rules(t, decodeRendered(t, cfg))
	for _, r := range rs {
		if !sameStringSet(r, "source", direct) || r.Has("domain") || r.Has("ip") {
			continue
		}
		if tag, _ := r.GetString("outboundTag"); tag == "direct" {
			return
		}
	}
	t.Error("a direct-based profile has no fallthrough, so its devices would be " +
		"proxied by the catch-all")
}

// Without a fallback there is no balancer, and the rules must name the outbound
// directly — a balancerTag pointing at nothing routes nowhere.
func TestWithoutAFallbackRulesNameTheOutbound(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := loadFixture(t, "profiles")
	if cfg.Fallback != nil {
		t.Skip("this fixture configures a fallback")
	}

	rs := rules(t, decodeRendered(t, cfg))
	sawProxy := false
	for i, r := range rs {
		if r.Has("balancerTag") {
			t.Errorf("rule %d uses a balancer, but none is declared: %v", i, r.Keys())
		}
		if tag, _ := r.GetString("outboundTag"); tag == "proxy" {
			sawProxy = true
		}
	}
	if !sawProxy {
		t.Error("no rule targets the proxy outbound at all")
	}
}

// configWithFallbackAndProfile builds the combination the fixtures do not
// cover: a fallback and a profile that inherits from proxy.
func configWithFallbackAndProfile(t *testing.T) *config.Config {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "tests/fixtures/reality-fallback.toml"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw) + `
[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via     = "direct"
  domains = ["domain:corp.example"]

[[client]]
ip     = "192.168.1.70"
name   = "laptop"
policy = "work-laptop"
`
	path := filepath.Join(root, "tests", "fixtures",
		".tmp-"+strings.ReplaceAll(t.Name(), "/", "-")+".toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

// Blocked networks are a global drop: they must land ahead of every rule that
// could route the same traffic somewhere, including a per-client policy and a
// profile's own exceptions. A block that a device-specific rule can overtake is
// not a block.
func TestBlockedNetworksBeatEveryRoutingRule(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := loadFixture(t, "reality-fallback")
	if len(cfg.BlockGeoIP) == 0 {
		t.Fatal("the fixture no longer configures blocked networks")
	}

	rs := rules(t, decodeRendered(t, cfg))
	blocked := -1
	for i, r := range rs {
		tag, _ := r.GetString("outboundTag")
		if tag == "block" && sameStringSet(r, "ip", cfg.BlockGeoIP) {
			blocked = i
			break
		}
	}
	if blocked < 0 {
		t.Fatal("routing.block_geoip produced no rule at all")
	}

	// Only the api rule and position="first" custom rules may precede it —
	// both are deliberately above the block section.
	for i, r := range rs[:blocked] {
		if r.Has("source") {
			t.Errorf("rule %d matches specific clients before the network block "+
				"at %d, so those clients would reach a blocked network", i, blocked)
		}
	}
}

// ------------------------------------------------------ upstream probing --

const upstreamFixture = `
[[upstream]]
name     = "work"
json     = """{"protocol":"freedom","settings":{}}"""
location = "outside"
dns      = "172.30.0.53"

[[upstream]]
name     = "home"
json     = """{"protocol":"freedom","settings":{}}"""
location = "inside"

[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via     = "work"
  domains = ["domain:corp.example"]

[[client]]
ip     = "192.168.1.70"
name   = "laptop"
policy = "work-laptop"
`

// An upstream that cannot be tested on its own can only be tested through
// whatever routing happens to send its way, so "is the work server up?" is not
// a question the box can answer — and a dead upstream looks like a broken
// profile.
func TestEachUpstreamHasItsOwnProbeInbound(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := configWith(t, upstreamFixture)
	doc := decodeRendered(t, cfg)

	inbounds, ok := doc.GetArray("inbounds")
	if !ok {
		t.Fatal("no inbounds")
	}
	ports := map[string]int{}
	for _, raw := range inbounds {
		in, ok := raw.(*jsonx.Object)
		if !ok {
			continue
		}
		tag, _ := in.GetString("tag")
		listen, _ := in.GetString("listen")
		if !strings.HasPrefix(tag, "probe-") {
			continue
		}
		if listen != "127.0.0.1" {
			t.Errorf("%s listens on %q — a probe port reachable from the LAN is "+
				"an unauthenticated way into the tunnel", tag, listen)
		}
		raw, _ := in.GetNumber("port")
		port, err := raw.Int64()
		if err != nil {
			t.Errorf("%s has a non-numeric port %q", tag, raw)
		}
		ports[tag] = int(port)
	}

	for _, u := range cfg.Upstreams {
		tag := "probe-" + u.Name + "-in"
		if ports[tag] == 0 {
			t.Errorf("upstream %q has no probe inbound", u.Name)
		}
		if ports[tag] != u.ProbePort {
			t.Errorf("upstream %q probes on %d, but the config says %d",
				u.Name, ports[tag], u.ProbePort)
		}
	}
	if len(ports) != len(cfg.Upstreams) {
		t.Errorf("got %d probe inbounds for %d upstreams", len(ports), len(cfg.Upstreams))
	}
	// Two upstreams sharing a port would silently probe the same server twice.
	seen := map[int]string{}
	for tag, port := range ports {
		if other, dup := seen[port]; dup {
			t.Errorf("%s and %s both listen on %d", tag, other, port)
		}
		seen[port] = tag
	}
}

// The probe must reach its own upstream and nothing else: a geo split or a
// block rule claiming it would make the answer describe the routing instead of
// the server.
func TestProbeTrafficIsNotDivertedByOtherRules(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := configWith(t, upstreamFixture)
	rs := rules(t, decodeRendered(t, cfg))

	for _, u := range cfg.Upstreams {
		tag := "probe-" + u.Name + "-in"
		at := -1
		for i, r := range rs {
			if hasStringItem(r, "inboundTag", tag) {
				at = i
				if got, _ := r.GetString("outboundTag"); got != u.Outbound.Tag {
					t.Errorf("%s routes to %q, want %q", tag, got, u.Outbound.Tag)
				}
				break
			}
		}
		if at < 0 {
			t.Errorf("nothing routes %s, so the probe follows the ordinary rules", tag)
			continue
		}
		// Only rules keyed on another inbound may precede it. Those cannot
		// match this probe's traffic; anything else could.
		for i, r := range rs[:at] {
			if _, keyed := r.GetArray("inboundTag"); keyed {
				continue
			}
			t.Errorf("rule %d could claim %s before it reaches its upstream: %v",
				i, tag, r.Keys())
		}
	}
}

// ------------------------------------------------------------ profile dns --

// Names a profile sends through an upstream have to be RESOLVED through it.
//
// Xray's own DNS queries carry no client address, so every profile rule — all
// of which match on source — misses them, and the name is answered from the
// wrong side of the tunnel. For a network that answers its own names
// differently, that is the outside view or nothing at all.
func TestProfileDomainsResolveThroughTheirUpstream(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := configWith(t, upstreamFixture)
	rs := rules(t, decodeRendered(t, cfg))

	found := false
	for _, r := range rs {
		if !hasStringItem(r, "inboundTag", "dns-in") {
			continue
		}
		if !hasStringItem(r, "domain", "domain:corp.example") {
			continue
		}
		found = true
		if tag, _ := r.GetString("outboundTag"); tag != "up-work" {
			t.Errorf("the DNS query for a work name goes to %q, not the work upstream", tag)
		}
	}
	if !found {
		t.Error("no rule routes the DNS query for a profile-routed name, so it " +
			"resolves through the main tunnel instead")
	}
}

// And it is asked of the resolver that knows the answer, ahead of the public
// servers — a corporate name falling through to a public resolver comes back
// with the outside view, or NXDOMAIN.
func TestUpstreamResolverWinsOverThePublicOnes(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := configWith(t, upstreamFixture)
	doc := decodeRendered(t, cfg)

	dns, ok := doc.GetObject("dns")
	if !ok {
		t.Fatal("no dns section")
	}
	servers, _ := dns.GetArray("servers")

	at := -1
	for i, raw := range servers {
		srv, ok := raw.(*jsonx.Object)
		if !ok {
			continue
		}
		if addr, _ := srv.GetString("address"); addr == "172.30.0.53" {
			at = i
			if !hasStringItem(srv, "domains", "domain:corp.example") {
				t.Error("the upstream resolver is not scoped to the names routed there")
			}
		}
	}
	if at < 0 {
		t.Fatal("the upstream's declared resolver is not in the DNS servers")
	}
	for i, raw := range servers[at+1:] {
		if _, isPlain := raw.(string); isPlain {
			continue // a bare DoH URL, which is the general fallback
		}
		_ = i
	}
	// It must not sit after the general domestic server, which claims geosite
	// ranges broadly enough to swallow a corporate name.
	for i, raw := range servers[:at] {
		srv, ok := raw.(*jsonx.Object)
		if !ok {
			continue
		}
		if hasStringItem(srv, "domains", "geosite:private") {
			t.Errorf("server %d claims domestic names before the upstream resolver at %d",
				i, at)
		}
	}
}

// An upstream with no declared resolver still gets the routing rule: the query
// rides the upstream even when the answer comes from a public server, which is
// what makes a split-horizon name resolve from the right side.
func TestUpstreamWithoutAResolverStillRoutesItsQueries(t *testing.T) {
	t.Chdir(repoRoot(t))
	cfg := configWith(t, `
[[upstream]]
name = "work"
json = """{"protocol":"freedom","settings":{}}"""

[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via     = "work"
  domains = ["domain:corp.example"]

[[client]]
ip     = "192.168.1.70"
name   = "laptop"
policy = "work-laptop"
`)
	rs := rules(t, decodeRendered(t, cfg))
	for _, r := range rs {
		if hasStringItem(r, "inboundTag", "dns-in") &&
			hasStringItem(r, "domain", "domain:corp.example") {
			return
		}
	}
	t.Error("no DNS routing rule without a declared resolver")
}

// configWith renders the default fixture plus an appended section.
func configWith(t *testing.T, body string) *config.Config {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "tests/fixtures/default.toml"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "tests", "fixtures",
		".tmp-"+strings.ReplaceAll(t.Name(), "/", "-")+".toml")
	if err := os.WriteFile(path, []byte(string(raw)+"\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}
