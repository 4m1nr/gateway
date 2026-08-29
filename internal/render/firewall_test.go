package render

import (
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
