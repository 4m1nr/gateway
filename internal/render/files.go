package render

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/config"
)

// RouteTable is the policy-routing table the TPROXY mark diverts into. Its only
// route is `local default dev lo`, which is what makes the kernel deliver
// marked packets locally instead of forwarding them.
const RouteTable = 100

// NFT renders the nftables ruleset.
//
// This file decides WHETHER a client is intercepted; Xray decides WHERE an
// intercepted flow goes. It is fail-closed by construction: the forward chain
// has no accept path for @proxy_clients, so if Xray is not listening the packet
// reaches a terminal drop rather than finding a way out.
func NFT(c *config.Config, generatedAt time.Time) (string, error) {
	tpl, err := templateFile("gateway.nft.tmpl")
	if err != nil {
		return "", err
	}

	var v6Pre, v6Out, v6Fwd string
	if c.IPv6Mode == "off" {
		v6Pre = "        meta nfproto ipv6 iifname != \"tailscale0\" " +
			"counter drop comment \"ipv6-dropped\"\n"
		v6Out = "        meta nfproto ipv6 return\n"
		v6Fwd = "        meta nfproto ipv6 iifname != \"tailscale0\" " +
			"oifname != \"tailscale0\" counter drop " +
			"comment \"ipv6-forward-dropped\"\n"
	}

	// TPROXY runs at mangle priority (-150) and nat prerouting at dstnat
	// (-100), so an unqualified tproxy rule would swallow port 53 before the
	// redirect below ever ran — leaving dns.intercept enabled and inert.
	dnsExclude := ""
	if c.DNSIntercept {
		dnsExclude = "th dport != 53 "
	}

	// The catch-all that makes "point your gateway here and you are proxied"
	// true. It matches $LAN in the forward path only, so it applies to exactly
	// the devices that opted in — a device using the router as its gateway
	// never sends a packet through this chain.
	//
	// A profile is intercepted exactly like a plain proxy client: splitting
	// traffic by destination requires Xray to see it.
	var preDefault, fwdDefault, postDefault string
	switch {
	case c.Intercepted[c.DefaultPolicy]:
		preDefault = "        meta l4proto { tcp, udp } ip saddr $LAN " + dnsExclude + "\\\n" +
			"            meta mark set $MARK_TPROXY counter \\\n" +
			"            tproxy ip to :$TPROXY_PORT accept " +
			"comment \"lan-intercepted\"\n"
		// Same kill switch as for listed clients: if Xray is not listening the
		// TPROXY rule above does not match, and this drop is what stops the
		// packet finding a direct way out.
		fwdDefault = "        ip saddr $LAN counter drop comment \"killswitch-default\"\n"
	case c.DefaultPolicy == "direct":
		preDefault = "        ip saddr $LAN return\n"
		fwdDefault = "        ip saddr $LAN accept\n"
		postDefault = "        oifname $WAN ip saddr $LAN masquerade\n"
	default: // block
		preDefault = "        ip saddr $LAN drop\n"
	}

	poisonedRule := "        # routing.drop_private_destinations = false\n"
	if len(c.PoisonedDst()) > 0 {
		poisonedRule = "        ip daddr @poisoned_dst counter drop comment \"poisoned-dns\"\n"
	}

	// Both the set and the rule appear only when a route actually names private
	// space. An empty set, and a rule that can never match, are dead weight in a
	// file every packet on the box is matched against.
	setRouted, routedRule := "", ""
	if routed := c.RoutedPrivate(); len(routed) > 0 {
		setRouted = "    set routed_dst {\n" +
			"        type ipv4_addr\n" +
			"        flags interval\n" +
			"        comment \"private space a route sends through an outbound\"\n" +
			nftElements(routed, 8) +
			"    }\n\n"
		routedRule = "        # Private ranges a profile or custom route deliberately sends\n" +
			"        # through an outbound. Ahead of the bypass below, which would\n" +
			"        # return them as local business and put them out of the WAN --\n" +
			"        # leaving Xray with a correct rule it never gets to apply, and a\n" +
			"        # work network unreachable for exactly the devices meant to reach\n" +
			"        # it. @proxy_clients excludes blocked and opted-out devices, which\n" +
			"        # are checked further down.\n" +
			"        meta l4proto { tcp, udp } ip daddr @routed_dst " +
			"ip saddr @proxy_clients " + dnsExclude + "\\\n" +
			"            meta mark set $MARK_TPROXY counter \\\n" +
			"            tproxy ip to :$TPROXY_PORT accept comment \"routed-private\"\n\n"
	}

	// Catches clients pointed at a public resolver. One pointed at the router
	// resolves over the local segment and never reaches this box at all — for
	// those, the router's DHCP has to hand out this box as the DNS server.
	dnsChain := "    # dns.intercept = false\n"
	if c.DNSIntercept {
		dnsChain = "    chain dnsintercept {\n" +
			"        type nat hook prerouting priority dstnat; policy accept;\n" +
			"        # Opted-out clients keep whatever resolver they chose.\n" +
			"        ip saddr @direct_clients return\n" +
			"        ip daddr $BOX return\n" +
			"        ip saddr $LAN meta l4proto { tcp, udp } th dport 53 \\\n" +
			fmt.Sprintf("            dnat ip to $BOX:%d\n", c.DNSPort) +
			"    }\n"
	}

	sshRule := ""
	if c.SSHAllowLAN {
		sshRule = "        ip saddr $LAN tcp dport 22 accept\n"
	}
	// AdGuard's admin interface. An empty list means the port is never opened,
	// which is a thing to want: AdGuard has its own password, but it is one
	// more login on one more port.
	uiRule := fmt.Sprintf("        # AdGuard admin interface (port %d) is not "+
		"opened: dns.ui_enabled = false\n", c.UIPort)
	if len(c.UIAllow) > 0 {
		uiRule = "        # AdGuard admin interface, restricted to dns.ui_allow_cidrs\n" +
			fmt.Sprintf("        ip saddr { %s } tcp dport %d accept\n",
				strings.Join(c.UIAllow, ", "), c.UIPort)
	}

	// First of the dashboard's three gates. The app re-checks the peer itself;
	// this is what stops a packet from an unlisted source arriving at all.
	webRule := ""
	if c.WebEnabled && len(c.WebAllow) > 0 {
		webRule = "        # web dashboard, restricted to web.allow_cidrs\n" +
			fmt.Sprintf("        ip saddr { %s } tcp dport %d accept\n",
				strings.Join(c.WebAllow, ", "), c.WebPort)
	}

	directElems := append(c.ClientsBy("direct"), tailnetIf(c.TailnetDirect())...)
	blockedElems := append(c.ClientsBy("block"), tailnetIf(c.TailnetBlocked())...)

	return subst(tpl, map[string]string{
		"CONFIG_PATH":   c.Path,
		"GENERATED_AT":  generatedAt.Format("2006-01-02T15:04:05-07:00"),
		"WAN_IF":        c.WANIf,
		"LAN_CIDR":      c.LANCidr,
		"BOX_IP":        c.BoxIP,
		"ROUTER":        c.Router,
		"TPROXY_PORT":   strconv.Itoa(c.TproxyPort),
		"MARK_TPROXY":   "1",
		"MARK_XRAY":     strconv.Itoa(c.OutboundMark),
		"DNS_PORT":      strconv.Itoa(c.DNSPort),
		"ELEM_PROXY":    nftElements(c.ProxySources(), 8),
		"ELEM_DIRECT":   nftElements(directElems, 8),
		"ELEM_BLOCKED":  nftElements(blockedElems, 8),
		"ELEM_BYPASS":   nftElements(c.BypassDst(), 8),
		"ELEM_POISONED": nftElements(c.PoisonedDst(), 8),
		// Always empty. The tailscaled exemption is a cgroup match, and
		// nftables resolves the cgroup path to an ID at insertion time — at
		// boot tailscaled has no cgroup yet, so the rule is added later by
		// gw-tailscale-exception.service instead of being baked in here.
		"ELEM_EXCEPTIONS":     "",
		"IPV6_PREROUTING":     v6Pre,
		"IPV6_OUTPUT":         v6Out,
		"IPV6_FORWARD":        v6Fwd,
		"PREROUTING_DEFAULT":  preDefault,
		"FORWARD_DEFAULT":     fwdDefault,
		"POSTROUTING_DEFAULT": postDefault,
		"POISONED_RULE":       poisonedRule,
		"SET_ROUTED":          setRouted,
		"ROUTED_RULE":         routedRule,
		"DNS_INTERCEPT":       dnsChain,
		"DNS_EXCLUDE":         dnsExclude,
		"INPUT_SSH":           sshRule,
		"INPUT_UI":            uiRule,
		"INPUT_WEB":           webRule,
	})
}

func tailnetIf(cond bool) []string {
	if cond {
		return []string{config.TailnetV4}
	}
	return nil
}

// Sysctl renders the kernel settings the gateway depends on.
func Sysctl(c *config.Config) (string, error) {
	tpl, err := templateFile("sysctl.conf.tmpl")
	if err != nil {
		return "", err
	}
	var v6 string
	if c.IPv6Mode == "off" {
		v6 = "# IPv6 off on the LAN side only. A blanket all.disable_ipv6 would\n" +
			"# break Tailscale, which uses IPv6 for its own tailnet addressing.\n" +
			fmt.Sprintf("net.ipv6.conf.%s.disable_ipv6 = 1\n", c.WANIf) +
			fmt.Sprintf("net.ipv6.conf.%s.accept_ra = 0\n", c.WANIf) +
			"\n" +
			"# IPv6 forwarding stays ON even with IPv6 off on the LAN, and it is\n" +
			"# the tailnet that needs it. `--advertise-exit-node` advertises\n" +
			"# ::/0 as well as 0.0.0.0/0 — there is no v4-only exit node — so\n" +
			"# Tailscale checks v6 forwarding and reports the box as broken\n" +
			"# without it: \"Subnet routing is enabled, but IP forwarding is\n" +
			"# disabled.\"\n" +
			"#\n" +
			"# It also matches what the firewall already allows: the ruleset\n" +
			"# drops IPv6 everywhere except from tailscale0, so leaving the\n" +
			"# kernel knob off meant the two disagreed, with the kernel\n" +
			"# silently winning. The LAN side cannot leak either way, because\n" +
			fmt.Sprintf("# %s has no IPv6 at all.\n", c.WANIf) +
			"net.ipv6.conf.all.forwarding = 1\n" +
			"net.ipv6.conf.default.forwarding = 1\n"
	} else {
		v6 = "net.ipv6.conf.all.forwarding = 1\n" +
			"net.ipv6.conf.default.forwarding = 1\n"
	}
	bbr := ""
	if c.BBR {
		bbr = "net.core.default_qdisc = fq\n" +
			"net.ipv4.tcp_congestion_control = bbr\n"
	}
	return subst(tpl, map[string]string{
		"WAN_IF": c.WANIf, "IPV6_SYSCTL": v6, "BBR_SYSCTL": bbr,
	})
}

// Network renders the systemd-networkd unit for the WAN interface.
func Network(c *config.Config) (string, error) {
	tpl, err := templateFile("wan.network.tmpl")
	if err != nil {
		return "", err
	}
	v6 := "IPv6AcceptRA=yes\n"
	if c.IPv6Mode == "off" {
		v6 = "IPv6AcceptRA=no\nLinkLocalAddressing=no\n"
	}
	return subst(tpl, map[string]string{
		"WAN_IF":       c.WANIf,
		"BOX_IP":       c.BoxIP,
		"ROUTER":       c.Router,
		"PREFIX_LEN":   strconv.Itoa(c.PrefixLen),
		"IPV6_NETWORK": v6,
	})
}

// Env renders shell-sourceable settings for the helper scripts.
//
// Every value is quoted: this file is `.`-sourced, so an unquoted value
// containing a space (GEO_FILES, a proxy URL with odd characters) would be
// parsed as a command. Readers that want a single value should source the file
// rather than grepping it.
func Env(c *config.Config, repo string) (string, error) {
	pairs := [][2]string{
		{"REPO", repo},
		// Only used by jobs that need the internet before the tunnel exists;
		// unused once the gateway carries its own traffic.
		{"BOOTSTRAP_PROXY", c.BootstrapProxy},
		// Geodata settings are no longer exported: `gw agent geoupdate` reads
		// the config directly, and there can be several sources now, which a
		// flat KEY=value file cannot express without lying about it.
		{"GEO_MIN_BYTES", strconv.Itoa(c.GeoMinBytes)},
		{"WAN_IF", c.WANIf},
		{"LAN_CIDR", c.LANCidr},
		{"BOX_IP", c.BoxIP},
		{"ROUTER", c.Router},
		{"TPROXY_PORT", strconv.Itoa(c.TproxyPort)},
		{"SOCKS_PORT", strconv.Itoa(c.SocksPort)},
		{"HTTP_PORT", strconv.Itoa(c.HTTPPort)},
		{"API_PORT", strconv.Itoa(c.APIPort)},
		{"MARK_TPROXY", "1"},
		{"MARK_XRAY", strconv.Itoa(c.OutboundMark)},
		{"RT_TABLE", strconv.Itoa(RouteTable)},
		{"PROBE_URL", c.ProbeURL},
		{"PROBE_TIMEOUT", strconv.Itoa(c.ProbeTimeout)},
		{"DOMESTIC_PROBE_URL", c.DomesticProbeURL},
		{"INTERVAL", strconv.Itoa(c.HealthInterval)},
		{"RESTART_AFTER", strconv.Itoa(c.RestartAfter)},
		{"FALLBACK_AFTER", strconv.Itoa(c.FallbackAfter)},
		{"LIFELINE_MIN", strconv.Itoa(lifelineMin(c))},
		{"UI_PORT", strconv.Itoa(c.UIPort)},
		{"DNS_PORT", strconv.Itoa(c.DNSPort)},
		// So `gw check` can tell "intercept is off by choice" from "the chain
		// is missing because apply never ran".
		{"DNS_INTERCEPT", boolString(c.DNSIntercept)},
		{"DEFAULT_POLICY", c.DefaultPolicy},
		// Consumed by `gw client` and the dashboard so both offer exactly the
		// policies this config defines.
		{"POLICIES", strings.Join(c.Policies, ",")},
		{"PROFILES", strings.Join(c.ProfileNames(), ",")},
	}
	lines := []string{
		"# Generated by `gw apply` — consumed by the gateway helper scripts",
		"# Values are quoted; source this file, do not grep it.",
	}
	for _, kv := range pairs {
		if strings.ContainsAny(kv[1], "\"\\") {
			return "", fmt.Errorf("%s contains a quote or backslash: %q", kv[0], kv[1])
		}
		lines = append(lines, fmt.Sprintf("%s=%q", kv[0], kv[1]))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

func lifelineMin(c *config.Config) int {
	if !c.TSEnabled {
		return 0
	}
	return c.TSLifelineMin
}

// TargetWants lists the third-party units the gateway stack pulls in at boot.
func TargetWants(c *config.Config) string {
	lines := []string{"Wants=AdGuardHome.service", "After=AdGuardHome.service"}
	if c.WebEnabled {
		lines = append(lines, "Wants=gw-web.service")
	}
	if c.TSEnabled {
		// Wanted, but deliberately NOT PartOf the target: a restart of the
		// stack must not drop the Tailscale session you are managing it over.
		lines = append(lines, "Wants=tailscaled.service")
	}
	return strings.Join(lines, "\n") + "\n"
}

// TailscaleArgs renders the flags `tailscale up` is invoked with.
func TailscaleArgs(c *config.Config) string {
	if !c.TSEnabled {
		return "# tailscale.enabled = false\n"
	}
	args := []string{"--accept-dns=false", "--accept-routes=false"}
	if c.TSSSH {
		args = append(args, "--ssh")
	}
	if c.TSExitNode {
		args = append(args, "--advertise-exit-node")
	}
	if c.TSSubnetRouter {
		args = append(args, "--advertise-routes="+c.LANCidr)
	}
	return strings.Join(args, " ") + "\n"
}

// boolString renders a flag for the env file the shell helpers source.
func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
