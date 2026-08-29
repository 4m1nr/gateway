package render

import (
	"encoding/json"
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
