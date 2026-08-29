package config

import (
	"net/netip"
	"strings"
	"testing"
)

// PoisonedDst is RFC1918 minus what is genuinely reachable. Getting it wrong in
// either direction is a real outage: too wide and local traffic is dropped, too
// narrow and a poisoned DNS answer escapes unintercepted and dies mid-handshake
// looking like a broken tunnel.
func TestPoisonedDst(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		local []string // addresses that must NOT be matched
		hit   []string // addresses that MUST be matched
	}{
		{
			name:  "default LAN",
			body:  "",
			local: []string{"192.168.1.1", "192.168.1.254"},
			hit:   []string{"10.10.34.34", "172.16.5.5", "192.168.2.1", "10.0.0.1"},
		},
		{
			name:  "extra local network is spared",
			body:  "[routing]\nextra_local_networks = [\"10.20.0.0/16\"]",
			local: []string{"192.168.1.50", "10.20.0.1", "10.20.255.254"},
			hit:   []string{"10.10.34.34", "10.21.0.1", "172.16.5.5"},
		},
		{
			name:  "a LAN inside 10/8",
			body:  "[net]\nwan_if=\"eth0\"\nlan_cidr=\"10.10.34.0/24\"\nrouter=\"10.10.34.1\"\nstatic_ip=\"10.10.34.2\"",
			local: []string{"10.10.34.34"},
			hit:   []string{"10.10.35.1", "10.0.0.1", "192.168.1.1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.body
			// A [net] override in the body replaces the base one, so strip it.
			base := minimalBase
			if strings.Contains(body, "[net]") {
				base = strings.Replace(base, `
[net]
wan_if    = "eth0"
lan_cidr  = "192.168.1.0/24"
router    = "192.168.1.1"
static_ip = "192.168.1.2"
`, "\n", 1)
			}
			cfg, err := loadWithBase(t, base, body)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			nets := mustPrefixes(t, cfg.PoisonedDst())
			if len(nets) == 0 {
				t.Fatal("poisoned_dst is empty; a poisoned DNS answer would go unintercepted")
			}
			if covers(nets, cfg.LAN) {
				t.Errorf("poisoned_dst overlaps the LAN %s — local traffic would be dropped", cfg.LANCidr)
			}
			for _, ip := range tc.local {
				if matches(nets, ip) {
					t.Errorf("%s is reachable here but poisoned_dst matches it", ip)
				}
			}
			for _, ip := range tc.hit {
				if !matches(nets, ip) {
					t.Errorf("%s should be treated as a poisoned answer but is not matched", ip)
				}
			}
		})
	}
}

func TestPoisonedDstDisabled(t *testing.T) {
	cfg, err := loadWith(t, "[routing]\ndrop_private_destinations = false")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.PoisonedDst(); len(got) != 0 {
		t.Errorf("drop_private_destinations = false still produced %v", got)
	}
}

// A profile client is intercepted even with base = "direct": splitting traffic
// by destination requires Xray to see it.
func TestProfileClientsAreIntercepted(t *testing.T) {
	cfg, err := loadWith(t, `
[[profile]]
name = "work"
base = "direct"
[[profile.route]]
via = "proxy"
domains = ["domain:corp.example"]

[[client]]
ip = "192.168.1.70"
name = "laptop"
policy = "work"

[[client]]
ip = "192.168.1.60"
name = "tv"
policy = "direct"
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	src := cfg.ProxySources()
	if !contains(src, "192.168.1.70") {
		t.Errorf("profile client is not intercepted; proxy_sources = %v", src)
	}
	if contains(src, "192.168.1.60") {
		t.Errorf("a direct client must not be intercepted; proxy_sources = %v", src)
	}
}

// When a profile is the LAN default, it applies to every unlisted device.
func TestProfileSourcesIncludeLANWhenDefault(t *testing.T) {
	cfg, err := loadWith(t, `
[policy]
default = "split"

[[profile]]
name = "split"
[[profile.route]]
via = "direct"
domains = ["domain:local.example"]
`)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.ProfileSources("split"); !contains(got, cfg.LANCidr) {
		t.Errorf("profile is the default but sources are %v, missing %s", got, cfg.LANCidr)
	}
}

func TestTailnetExitPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy          string
		direct, blocked bool
		inProxySources  bool
	}{
		{"proxy", false, false, true},
		{"direct", true, false, false},
		{"block", false, true, false},
	} {
		t.Run(tc.policy, func(t *testing.T) {
			cfg, err := loadWith(t, "[tailscale]\nexit_node_policy = \""+tc.policy+"\"")
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.TailnetDirect() != tc.direct || cfg.TailnetBlocked() != tc.blocked {
				t.Errorf("direct=%v blocked=%v, want %v/%v",
					cfg.TailnetDirect(), cfg.TailnetBlocked(), tc.direct, tc.blocked)
			}
			if got := contains(cfg.ProxySources(), TailnetV4); got != tc.inProxySources {
				t.Errorf("tailnet in proxy_sources = %v, want %v", got, tc.inProxySources)
			}
		})
	}
}

// ---------------------------------------------------------------- helpers --

func mustPrefixes(t *testing.T, cidrs []string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("poisoned_dst produced %q, which is not a CIDR: %v", c, err)
		}
		out = append(out, p)
	}
	return out
}

func matches(nets []netip.Prefix, ip string) bool {
	addr := netip.MustParseAddr(ip)
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}

func covers(nets []netip.Prefix, lan netip.Prefix) bool {
	for _, n := range nets {
		if n.Overlaps(lan) {
			return true
		}
	}
	return false
}
