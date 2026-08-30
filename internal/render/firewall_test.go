package render

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/am1nr/gateway/internal/config"
)

// chain extracts one nftables chain body.
func chain(t *testing.T, ruleset, name string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)chain ` + name + ` \{(.*?)\n    \}`)
	m := re.FindStringSubmatch(ruleset)
	if m == nil {
		t.Fatalf("no %s chain in the ruleset", name)
	}
	return m[1]
}

func renderNFT(t *testing.T, name string) (*config.Config, string) {
	t.Helper()
	t.Chdir(repoRoot(t))
	cfg := loadFixture(t, name)
	ruleset, err := NFT(cfg, fixedTime)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return cfg, ruleset
}

// indexOf reports where a substring first appears, or -1.
func indexOf(haystack, needle string) int { return strings.Index(haystack, needle) }

// The kill switch is what makes the gateway fail-closed. Without it a client
// whose traffic misses TPROXY — because Xray is not listening — finds a direct
// way out instead of losing connectivity, and the whole promise of the design
// quietly inverts.
func TestKillswitchPresent(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			cfg, ruleset := renderNFT(t, name)
			if !strings.Contains(ruleset, `comment "killswitch"`) {
				t.Fatal("the killswitch rule is missing — traffic would leak instead of failing closed")
			}
			// There must be no accept path for intercepted clients in forward.
			fwd := chain(t, ruleset, "forward")
			for _, line := range strings.Split(fwd, "\n") {
				if strings.Contains(line, "@proxy_clients") && strings.Contains(line, "accept") {
					t.Errorf("forward accepts @proxy_clients directly, which defeats the killswitch:\n  %s", line)
				}
			}
			// An intercepted default needs its own catch-all drop.
			if cfg.Intercepted[cfg.DefaultPolicy] &&
				!strings.Contains(fwd, `comment "killswitch-default"`) {
				t.Error("the LAN default is intercepted but has no killswitch-default drop")
			}
		})
	}
}

// The box's own traffic is marked in output, looped back through lo by policy
// routing, and can only be intercepted in prerouting. If the loopback shortcut
// comes first, those packets vanish and the box has no internet while LAN
// clients work — a genuinely awful thing to debug.
func TestLoopedBackTrafficIsInterceptedBeforeTheLoShortcut(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			_, ruleset := renderNFT(t, name)
			pre := chain(t, ruleset, "prerouting")
			tproxy := indexOf(pre, "iif lo meta mark")
			ret := regexp.MustCompile(`(?m)^\s*iif lo return`).FindStringIndex(pre)
			if tproxy < 0 || ret == nil {
				t.Fatal("prerouting no longer has both the lo interception and the lo shortcut")
			}
			if tproxy > ret[0] {
				t.Error("prerouting returns on lo before intercepting marked local traffic — " +
					"the box will have no internet while LAN clients keep working")
			}
		})
	}
}

// A TPROXY-delivered packet is addressed to an external IP and delivered
// locally, which conntrack is inclined to call invalid. Accepting on the mark
// has to come first, or the client's SYNs die between the tproxy verdict and
// Xray's socket while the prerouting counters show them intercepted.
func TestInputAcceptsInterceptedBeforeTheConntrackCheck(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			_, ruleset := renderNFT(t, name)
			in := chain(t, ruleset, "input")
			mark := indexOf(in, "input-intercepted")
			invalid := indexOf(in, "input-invalid")
			if mark < 0 || invalid < 0 {
				t.Fatal("input no longer has both the intercepted accept and the ct-invalid drop")
			}
			if mark > invalid {
				t.Error("input drops ct-invalid before accepting intercepted packets")
			}
		})
	}
}

// Redirecting to a loopback address makes every packet arriving on a real
// interface a martian, dropped by the kernel during the route lookup — after
// the rule's counter has already counted it. The box's own traffic still works,
// so this looks like "clients are broken" rather than "the tproxy target is
// wrong".
func TestTproxyKeepsTheOriginalDestination(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			_, ruleset := renderNFT(t, name)
			if regexp.MustCompile(`tproxy ip to 127\.`).MatchString(ruleset) {
				t.Fatal("tproxy redirects to loopback — LAN clients will be dropped as martians")
			}
			if !strings.Contains(ruleset, "tproxy ip to :") {
				t.Fatal("no tproxy rule found")
			}
		})
	}
}

// dns.intercept only works if port 53 is excluded from tproxy: mangle runs at
// -150 and nat prerouting at -100, so tproxy would swallow it first and the
// redirect would sit there doing nothing.
func TestDNSInterceptIsReachable(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			cfg, ruleset := renderNFT(t, name)
			hasChain := strings.Contains(ruleset, "chain dnsintercept")
			if cfg.DNSIntercept != hasChain {
				t.Fatalf("dns.intercept = %v but the dnsintercept chain present = %v",
					cfg.DNSIntercept, hasChain)
			}
			if hasChain && !strings.Contains(ruleset, "dport != 53") {
				t.Error("the dnsintercept chain exists but tproxy still swallows port 53, " +
					"so the redirect never runs")
			}
		})
	}
}

// The dashboard's first gate. Widening this to everything the box can reach is
// refused at load time; here we check the ruleset actually narrows the port.
func TestWebPortIsRestrictedToAllowCidrs(t *testing.T) {
	for _, name := range fixtureNames(t) {
		t.Run(name, func(t *testing.T) {
			cfg, ruleset := renderNFT(t, name)
			in := chain(t, ruleset, "input")
			if !cfg.WebEnabled {
				if strings.Contains(in, "web dashboard") {
					t.Error("web.enabled is false but the ruleset still opens the dashboard port")
				}
				return
			}
			for _, cidr := range cfg.WebAllow {
				if !strings.Contains(in, cidr) {
					t.Errorf("input does not mention allow_cidrs entry %s", cidr)
				}
			}
			if !strings.Contains(in, "tcp dport "+itoa(cfg.WebPort)) {
				t.Errorf("input does not open the dashboard port %d", cfg.WebPort)
			}
		})
	}
}

// Every decision point should be counted. A silent drop is how the last few
// bugs stayed hidden: `gw diag` reads these counters to say which rule claimed
// a client's packets, and an uncounted one is invisible in that report.
//
// One known exception, carried over from the Python renderer unchanged: the
// forward chain's `ct state invalid drop` has neither a counter nor a comment,
// while the input chain's equivalent is `input-invalid`. Adding one is a
// one-line template change, but it would alter the generated ruleset, and this
// port is anchored on byte-identity with the frozen Python output — so it is
// named here rather than fixed silently.
var uncountedDrops = map[string]string{
	"forward": "ct state invalid drop",
}

func TestDropsAreCountedAndNamed(t *testing.T) {
	_, ruleset := renderNFT(t, "default")
	for _, chainName := range []string{"prerouting", "forward", "input"} {
		body := chain(t, ruleset, chainName)
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasSuffix(trimmed, "drop") && !strings.Contains(trimmed, "drop comment") {
				continue
			}
			if strings.HasPrefix(trimmed, "#") || strings.Contains(trimmed, "policy drop") {
				continue
			}
			if trimmed == uncountedDrops[chainName] {
				continue
			}
			if !strings.Contains(trimmed, "counter") {
				t.Errorf("%s has an uncounted drop, invisible to `gw diag`:\n  %s", chainName, trimmed)
			}
		}
	}
}

// The known exception must stay exactly one line in exactly one chain. If a
// second uncounted drop appears, or this one gains a counter, this test says so
// and the list above can be updated deliberately.
func TestUncountedDropInventoryIsUnchanged(t *testing.T) {
	_, ruleset := renderNFT(t, "default")
	found := map[string][]string{}
	for _, chainName := range []string{"prerouting", "forward", "input", "output", "postrouting"} {
		re := regexp.MustCompile(`(?s)chain ` + chainName + ` \{(.*?)\n    \}`)
		m := re.FindStringSubmatch(ruleset)
		if m == nil {
			continue
		}
		for _, line := range strings.Split(m[1], "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || strings.Contains(trimmed, "policy drop") {
				continue
			}
			if strings.HasSuffix(trimmed, "drop") && !strings.Contains(trimmed, "counter") {
				found[chainName] = append(found[chainName], trimmed)
			}
		}
	}
	if len(found) != len(uncountedDrops) {
		t.Fatalf("uncounted drops changed: got %v, expected only %v", found, uncountedDrops)
	}
	for chainName, lines := range found {
		want, ok := uncountedDrops[chainName]
		if !ok {
			t.Errorf("new uncounted drop in %s: %v", chainName, lines)
			continue
		}
		if len(lines) != 1 || lines[0] != want {
			t.Errorf("uncounted drops in %s changed: got %v, want exactly [%q]", chainName, lines, want)
		}
	}
}

// Narrowing who may reach a service has to reach the firewall, or the setting
// is a comment. These are the first gate for both the dashboard and AdGuard's
// admin interface.
func TestServicePortsFollowTheirAllowLists(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		open   map[int][]string // port -> networks that must appear
		closed []int
	}{
		{
			name: "defaults",
			body: "",
			open: map[int][]string{
				8088: {"192.168.1.0/24", "100.64.0.0/10"},
				3000: {"192.168.1.0/24"},
			},
		},
		{
			name: "dashboard over tailscale only",
			body: "[web]\nallow_cidrs = [\"100.64.0.0/10\"]",
			open: map[int][]string{8088: {"100.64.0.0/10"}},
		},
		{
			name: "adguard over tailscale as well",
			body: "[dns]\nui_allow_cidrs = [\"192.168.1.0/24\", \"100.64.0.0/10\"]",
			open: map[int][]string{3000: {"192.168.1.0/24", "100.64.0.0/10"}},
		},
		{
			name:   "adguard interface closed entirely",
			body:   "[dns]\nui_enabled = false",
			closed: []int{3000},
		},
		{
			name:   "dashboard disabled",
			body:   "[web]\nenabled = false",
			closed: []int{8088},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := loadWithSection(t, tc.body)
			ruleset, err := NFT(cfg, fixedTime)
			if err != nil {
				t.Fatal(err)
			}
			input := chain(t, ruleset, "input")

			for port, networks := range tc.open {
				line := findPortRule(input, port)
				if line == "" {
					t.Errorf("port %d is not opened at all", port)
					continue
				}
				for _, network := range networks {
					if !strings.Contains(line, network) {
						t.Errorf("port %d does not accept from %s:\n  %s", port, network, line)
					}
				}
				// Never from everywhere.
				if strings.Contains(line, "0.0.0.0/0") {
					t.Errorf("port %d is open to everything:\n  %s", port, line)
				}
			}
			for _, port := range tc.closed {
				if line := findPortRule(input, port); line != "" {
					t.Errorf("port %d should not be opened, but is:\n  %s", port, line)
				}
			}
		})
	}
}

// findPortRule returns the accept rule for a port, or "".
func findPortRule(chain string, port int) string {
	want := "dport " + itoa(port) + " accept"
	for _, line := range strings.Split(chain, "\n") {
		if strings.Contains(line, want) && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// loadWithSection appends a section to the default fixture and loads it.
func loadWithSection(t *testing.T, body string) *config.Config {
	t.Helper()
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "tests/fixtures/default.toml"))
	if err != nil {
		t.Fatal(err)
	}
	// The appended table wins for the keys it names; TOML rejects a duplicate
	// table, so the original is removed first where they collide.
	text := string(raw)
	for _, table := range []string{"[web]", "[dns]", "[routing]"} {
		if !strings.Contains(body, table) {
			continue
		}
		text = removeTable(text, table)
	}

	path := filepath.Join(root, "tests", "fixtures",
		".tmp-"+strings.ReplaceAll(t.Name(), "/", "-")+".toml")
	if err := os.WriteFile(path, []byte(text+"\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path) })

	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return cfg
}

// removeTable drops a top-level table and its keys, up to the next table.
func removeTable(text, header string) string {
	lines := strings.Split(text, "\n")
	var out []string
	skipping := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == header {
			skipping = true
			continue
		}
		if skipping {
			if strings.HasPrefix(trimmed, "[") {
				skipping = false
			} else {
				continue
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// A private range a route names is reachable through the outbound that names
// it.
//
// Two blanket rules about RFC1918 stood between a profile route and the network
// it pointed at: the poisoned-DNS drop killed the traffic outright, and the
// local-business bypass sent whatever survived out of the WAN. Xray's rule was
// generated correctly and never consulted, because the packets never reached
// Xray — so a work network was unreachable precisely for the device configured
// to reach it.
const workProfile = `
[[upstream]]
name = "work"
json = """{"protocol":"freedom","settings":{}}"""

[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via = "work"
  ips = ["172.30.0.0/16"]

[[client]]
ip     = "192.168.1.70"
name   = "laptop"
policy = "work-laptop"
`

func TestRoutedPrivateRangeIsNotDroppedAsPoisoned(t *testing.T) {
	cfg := loadWithSection(t, workProfile)
	for _, cidr := range cfg.PoisonedDst() {
		p := netip.MustParsePrefix(cidr)
		if p.Overlaps(netip.MustParsePrefix("172.30.0.0/16")) {
			t.Errorf("poisoned_dst contains %s, which covers the range the work "+
				"profile routes — the traffic is dropped before Xray sees it", cidr)
		}
	}
	// The rest of 172.16/12 must still be dropped: carving out one range is the
	// point, disabling the protection is not.
	var covered bool
	for _, cidr := range cfg.PoisonedDst() {
		if netip.MustParsePrefix(cidr).Overlaps(netip.MustParsePrefix("172.31.0.0/16")) {
			covered = true
		}
	}
	if !covered {
		t.Error("carving out the routed range disabled the poisoned-DNS drop for " +
			"the rest of 172.16.0.0/12")
	}
}

func TestRoutedPrivateIsInterceptedBeforeTheLocalBypass(t *testing.T) {
	cfg := loadWithSection(t, workProfile)
	ruleset, err := NFT(cfg, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	pre := chain(t, ruleset, "prerouting")

	routed := indexOf(pre, `comment "routed-private"`)
	bypass := indexOf(pre, `comment "bypass-local"`)
	if routed < 0 {
		t.Fatal("nothing intercepts the routed range; the bypass below claims it")
	}
	if bypass < 0 {
		t.Fatal("no bypass rule at all")
	}
	if routed > bypass {
		t.Error("the bypass returns the routed range before anything intercepts " +
			"it, so it leaves by the WAN instead of the upstream")
	}

	// And the set it matches has to hold the range, or the rule matches nothing.
	if !strings.Contains(ruleset, "172.30.0.0/16") {
		t.Error("172.30.0.0/16 is in no set, so the rule can never match")
	}
}

// The rule sits ahead of the blocked- and direct-client checks, so it has to
// exclude them itself. It does that by matching @proxy_clients, which a blocked
// or opted-out device is never in — but only as long as the guard is there.
func TestRoutedPrivateOnlyAppliesToInterceptedClients(t *testing.T) {
	cfg := loadWithSection(t, workProfile)
	ruleset, err := NFT(cfg, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	pre := chain(t, ruleset, "prerouting")

	for _, line := range strings.Split(pre, "\n") {
		if !strings.Contains(line, "@routed_dst") {
			continue
		}
		if !strings.Contains(line, "@proxy_clients") {
			t.Errorf("the routed-private rule does not check the source set, so a "+
				"blocked device would be intercepted rather than dropped:\n  %s", line)
		}
		return
	}
	t.Fatal("no rule matches @routed_dst")
}

// Nothing changes for a config whose routes name no private space: the rule is
// left out rather than pointing at an empty set in the path of every packet.
func TestNoRoutedRuleWithoutARoutedPrivateRange(t *testing.T) {
	_, ruleset := renderNFT(t, "default")
	if strings.Contains(ruleset, `comment "routed-private"`) {
		t.Error("a rule that can never match was added to the prerouting chain")
	}
}

// A geoip: tag names a file the config cannot read. It must be skipped rather
// than crashing the render or landing in a set as a literal.
func TestGeoTagsInRoutesAreNotTreatedAsAddresses(t *testing.T) {
	cfg := loadWithSection(t, `
[[profile]]
name = "tagged"
base = "proxy"

  [[profile.route]]
  via  = "direct"
  ips  = ["geoip:ir", "10.50.0.0/16"]

[[client]]
ip     = "192.168.1.71"
name   = "desk"
policy = "tagged"
`)
	got := cfg.RoutedPrivate()
	if len(got) != 1 || got[0] != "10.50.0.0/16" {
		t.Errorf("RoutedPrivate() = %v, want just the literal prefix", got)
	}
}

// Public addresses are none of this rule's business: they are neither dropped
// as poisoned nor returned as local, so they already reach Xray.
func TestOnlyPrivateRangesJoinTheRoutedSet(t *testing.T) {
	cfg := loadWithSection(t, `
[[profile]]
name = "pub"
base = "proxy"

  [[profile.route]]
  via  = "direct"
  ips  = ["203.0.113.0/24"]

[[client]]
ip     = "192.168.1.72"
name   = "desk2"
policy = "pub"
`)
	if got := cfg.RoutedPrivate(); len(got) != 0 {
		t.Errorf("RoutedPrivate() = %v, want nothing for a public range", got)
	}
}

// A network declared reachable has to be reachable from the devices that need
// the declaration.
//
// extra_local_networks kept these out of the poisoned-DNS drop and stopped
// there. Prerouting returns them as local business, which lands them in the
// forward chain, where the kill switch drops anything from a proxied client
// that was not intercepted. So the setting worked for unlisted devices, which
// were already fine, and did nothing for proxied ones — the symptom being a
// modem on its own subnet answering a plain laptop and not a proxied one.
const extraLocal = `
[routing]
extra_local_networks = ["192.168.0.0/24"]
`

func TestExtraLocalNetworksSurviveTheKillSwitch(t *testing.T) {
	cfg := loadWithSection(t, extraLocal)
	ruleset, err := NFT(cfg, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	fwd := chain(t, ruleset, "forward")

	local := indexOf(fwd, `comment "extra-local"`)
	kill := indexOf(fwd, `comment "killswitch"`)
	if local < 0 {
		t.Fatal("nothing in the forward chain lets a proxied device reach a " +
			"network declared local; the kill switch drops it")
	}
	if kill < 0 {
		t.Fatal("no kill switch in the forward chain")
	}
	if local > kill {
		t.Error("the kill switch runs first, so the declared network stays " +
			"unreachable from exactly the devices the setting exists for")
	}
	if !strings.Contains(ruleset, "192.168.0.0/24") {
		t.Error("the declared network is in no set, so the rule cannot match")
	}
}

// Blocking still wins. A blocked device must not reach a local network any more
// than it reaches the internet.
func TestBlockedClientsCannotReachExtraLocalNetworks(t *testing.T) {
	cfg := loadWithSection(t, extraLocal)
	ruleset, err := NFT(cfg, fixedTime)
	if err != nil {
		t.Fatal(err)
	}
	fwd := chain(t, ruleset, "forward")

	blocked := indexOf(fwd, `comment "blocked-client"`)
	local := indexOf(fwd, `comment "extra-local"`)
	if blocked < 0 || local < 0 {
		t.Fatal("expected both a blocked-client drop and an extra-local accept")
	}
	if blocked > local {
		t.Error("a blocked device would reach the local network: the accept " +
			"runs before the drop")
	}
}

// Nothing is added for a config that declares no extra networks.
func TestNoLocalRuleWithoutExtraLocalNetworks(t *testing.T) {
	_, ruleset := renderNFT(t, "default")
	if strings.Contains(ruleset, `comment "extra-local"`) {
		t.Error("a rule that can never match was added to the forward chain")
	}
	if strings.Contains(ruleset, "set local_dst") {
		t.Error("an empty set was added")
	}
}
