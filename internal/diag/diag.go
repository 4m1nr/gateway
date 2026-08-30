package diag

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Diag answers "where does this client's traffic actually go?" from the
// counters, rather than from reasoning about the ruleset.
//
// Every decision point in the firewall is counted, so one of these numbers
// moving identifies the rule that claimed the packets. That is the difference
// between reading the ruleset and knowing what it did.
type Diag struct {
	Client string `json:"client,omitempty"`

	Counters map[string][]Counter `json:"counters"`
	Sets     map[string][]string  `json:"sets"`

	DefaultPolicy string `json:"default_policy"`
	LANCidr       string `json:"lan_cidr"`

	Rules       []string          `json:"ip_rules"`
	RouteTables map[string]string `json:"route_tables"`
	RPFilter    map[string]string `json:"rp_filter"`
	KernelDrops map[string]string `json:"kernel_drops"`

	Forwarding Forwarding `json:"forwarding"`

	// Forward and Reverse are the kernel's own answers for a packet shaped like
	// this client's, which beats reasoning about the rules.
	Forward        string `json:"forward_route,omitempty"`
	ForwardVerdict string `json:"forward_verdict,omitempty"`
	Reverse        string `json:"reverse_route,omitempty"`

	InProxySet  string   `json:"in_proxy_set,omitempty"`
	InDirectSet string   `json:"in_direct_set,omitempty"`
	Conntrack   int      `json:"conntrack_entries"`
	XrayLines   []string `json:"xray_lines,omitempty"`

	XrayListening int `json:"xray_listening_sockets"`
}

// Counter is one counted rule and what it has matched.
type Counter struct {
	Name    string `json:"name"`
	Packets int64  `json:"packets"`
}

// Forwarding is the kernel's forwarding configuration.
type Forwarding struct {
	IPForward     string            `json:"ip_forward"`
	RPFilter      string            `json:"rp_filter"`
	SendRedirects string            `json:"send_redirects"`
	IPv6All       string            `json:"ipv6_all"`
	PerInterface  map[string]string `json:"per_interface"`
}

// diagChains are read in the order a packet meets them.
//
// dnsintercept is here because "this device is missing from AdGuard's query
// log" is otherwise unanswerable from the box: a device pointed at a resolver
// on its own segment never sends a packet through the gateway, which looks
// identical to a redirect that is not working.
var diagChains = []string{
	"prerouting", "dnsintercept", "input", "forward", "output", "postrouting",
}

var (
	counterRE = regexp.MustCompile(`counter packets (\d+)`)
	commentRE = regexp.MustCompile(`comment "([^"]+)"`)
)

// CollectDiag gathers everything about interception, optionally for one client.
func (c Collector) CollectDiag(client string) (Diag, error) {
	env := readEnv(c.envPath())
	d := Diag{
		Client:        client,
		Counters:      map[string][]Counter{},
		Sets:          map[string][]string{},
		RouteTables:   map[string]string{},
		RPFilter:      map[string]string{},
		KernelDrops:   map[string]string{},
		DefaultPolicy: env["DEFAULT_POLICY"],
		LANCidr:       env["LAN_CIDR"],
	}

	if _, err := run(5*time.Second, "nft", "list", "table", "inet", "gateway"); err != nil {
		return d, fmt.Errorf("the gateway table is not loaded — run 'sudo gw apply'")
	}
	for _, chain := range diagChains {
		d.Counters[chain] = chainCounters(chain)
	}
	for _, set := range []string{"proxy_clients", "direct_clients", "blocked_clients"} {
		d.Sets[set] = namedSetElements(set)
	}

	if out, err := run(5*time.Second, "ip", "rule", "list"); err == nil {
		d.Rules = nonEmptyLines(out)
	}
	for _, table := range routingTablesInPlay(d.Rules) {
		if out, err := run(5*time.Second, "ip", "route", "show", "table", table); err == nil {
			d.RouteTables[table] = strings.Join(strings.Fields(out), " ")
		}
	}

	d.Forwarding = readForwarding()
	d.RPFilter = perInterface("/proc/sys/net/ipv4/conf", "rp_filter")
	d.KernelDrops = kernelDropCounters()
	d.XrayListening = listeningOn(env["TPROXY_PORT"])

	if client != "" {
		c.diagClient(&d, client, env["WAN_IF"])
	}
	return d, nil
}

// diagClient asks the kernel what it does with a packet shaped like this
// client's, instead of reasoning about the rules.
func (c Collector) diagClient(d *Diag, client, wan string) {
	const probeDst = "1.1.1.1"

	// mark 1 is what TPROXY sets, so this is the lookup a marked packet gets.
	out, _ := runCombined(10*time.Second, "ip", "route", "get", probeDst,
		"from", client, "iif", wan, "mark", "1")
	d.Forward = strings.TrimSpace(out)
	switch {
	case strings.Contains(out, "Invalid argument"):
		d.ForwardVerdict = "EINVAL here means MARTIAN SOURCE: the kernel rejects this " +
			"client during reverse-path validation, which is exactly where " +
			"intercepted packets disappear."
	case strings.Contains(out, "local "):
		d.ForwardVerdict = "good: delivered locally, which is what TPROXY needs"
	}

	// The lookup that validates the reverse path. It runs with mark 0, so it
	// ignores the fwmark rule and can land in another table entirely.
	rev, _ := runCombined(10*time.Second, "ip", "route", "get", client, "from", probeDst)
	d.Reverse = strings.TrimSpace(rev)

	d.InProxySet = setMembership("proxy_clients", client,
		"no (covered by the LAN default if it is inside lan_cidr)")
	d.InDirectSet = setMembership("direct_clients", client, "no")

	if out, err := run(15*time.Second, "conntrack", "-L"); err == nil {
		d.Conntrack = strings.Count(out, "src="+client)
	} else {
		d.Conntrack = -1 // the tool is not installed
	}

	if out, err := run(15*time.Second, "journalctl", "-u", "xray", "-n", "200",
		"--no-pager", "-o", "cat"); err == nil {
		var hits []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, client) {
				hits = append(hits, line)
			}
		}
		d.XrayLines = lastN(hits, 5)
	}
}

// chainCounters reports every counted rule in a chain.
//
// An uncommented counter is reported by position rather than dropped, so a rule
// that lost its comment still appears — silently omitting it is how a decision
// point becomes invisible.
func chainCounters(chain string) []Counter {
	out, err := run(5*time.Second, "nft", "list", "chain", "inet", "gateway", chain)
	if err != nil {
		return nil
	}
	var counters []Counter
	unnamed := 0
	for _, line := range strings.Split(out, "\n") {
		m := counterRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		packets, _ := strconv.ParseInt(m[1], 10, 64)
		name := ""
		if c := commentRE.FindStringSubmatch(line); c != nil {
			name = c[1]
		} else {
			unnamed++
			name = fmt.Sprintf("(rule %d)", unnamed)
		}
		counters = append(counters, Counter{Name: name, Packets: packets})
	}
	return counters
}

// namedSetElements reads one set directly, which handles nft wrapping a long
// element list across lines.
func namedSetElements(set string) []string {
	out, err := run(5*time.Second, "nft", "list", "set", "inet", "gateway", set)
	if err != nil {
		return []string{}
	}
	return setElements(out, set)
}

func setMembership(set, element, absent string) string {
	if _, err := run(5*time.Second, "nft", "get", "element", "inet", "gateway",
		set, "{ "+element+" }"); err == nil {
		return "yes"
	}
	return absent
}

func routingTablesInPlay(rules []string) []string {
	seen := map[string]bool{}
	var out []string
	re := regexp.MustCompile(`lookup (\S+)`)
	for _, r := range rules {
		if m := re.FindStringSubmatch(r); m != nil && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func readForwarding() Forwarding {
	f := Forwarding{
		IPForward:     readTrimmed("/proc/sys/net/ipv4/ip_forward"),
		RPFilter:      readTrimmed("/proc/sys/net/ipv4/conf/all/rp_filter"),
		SendRedirects: readTrimmed("/proc/sys/net/ipv4/conf/all/send_redirects"),
		IPv6All:       readTrimmed("/proc/sys/net/ipv6/conf/all/forwarding"),
		PerInterface:  perInterface("/proc/sys/net/ipv4/conf", "forwarding"),
	}
	if f.IPv6All == "" {
		f.IPv6All = "n/a"
	}
	return f
}

// perInterface reads one sysctl for every real interface.
func perInterface(base, knob string) map[string]string {
	out := map[string]string{}
	entries, err := os.ReadDir(base)
	if err != nil {
		return out
	}
	for _, e := range entries {
		name := e.Name()
		if name == "all" || name == "default" {
			continue
		}
		if v := readTrimmed(filepath.Join(base, name, knob)); v != "" {
			out[name] = v
		}
	}
	return out
}

// kernelDropCounters reads the counters that -EXDEV drops land in and nowhere
// else.
func kernelDropCounters() map[string]string {
	out := map[string]string{}
	raw, err := run(10*time.Second, "nstat", "-az")
	if err != nil {
		return out
	}
	want := regexp.MustCompile(`(?i)rpfilter|martian|InAddrErrors|InNoRoutes`)
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && want.MatchString(f[0]) {
			out[f[0]] = f[1]
		}
	}
	return out
}

func listeningOn(port string) int {
	if port == "" {
		return 0
	}
	out, err := run(10*time.Second, "ss", "-lntup")
	if err != nil {
		return 0
	}
	return strings.Count(out, ":"+port)
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}
