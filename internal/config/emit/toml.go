// Package emit writes gateway.toml back out.
//
// The dashboard owns the whole file, which means a save rewrites it rather than
// patching regions of it. Two things follow from that, and both are deliberate:
//
// Every value that was read is written back, including keys this codebase does
// not model. Dropping an unrecognised key would silently delete a setting a
// future version added, or one a person put there on purpose.
//
// The output is documented. Hand-written comments cannot survive a rewrite, so
// the emitter carries its own: each section and each key it knows about gets
// the explanation from gateway.example.toml. The file stays readable and
// hand-editable after the dashboard has touched it.
package emit

import (
	"strings"
	"time"
)

// Document is the whole config, as decoded.
type Document map[string]any

// Emit renders a config as TOML.
func Emit(doc Document) ([]byte, error) {
	var b strings.Builder
	b.WriteString(header())

	written := map[string]bool{}

	for _, section := range layout {
		if err := section.write(&b, doc, written); err != nil {
			return nil, err
		}
	}

	// Anything the layout does not know about, so a key added by a future
	// version — or by hand — is preserved rather than quietly dropped.
	if err := writeRemainder(&b, doc, written); err != nil {
		return nil, err
	}

	return []byte(b.String()), nil
}

func header() string {
	return "# gateway.toml — the single source of truth for this gateway.\n" +
		"#\n" +
		"# Everything the box installs is generated from this file: run `gw apply`\n" +
		"# after any change. The dashboard writes this file too, and rewrites it\n" +
		"# whole — so the comments below are regenerated, not preserved.\n" +
		"#\n" +
		"# Last written by gw on " + time.Now().Format("2006-01-02 15:04") + ".\n"
}

// ------------------------------------------------------------------ layout --

// entry documents one key.
type entry struct {
	key string
	doc string
}

// section is one table in the file, in the order it should appear.
type section struct {
	// name is the TOML table name, or "" for the document root.
	name string
	// array marks an array-of-tables ([[name]]).
	array bool
	doc   string
	keys  []entry
}

// layout is the canonical order of the file: the things you change most often
// first, the things you set once last.
var layout = []section{
	{
		name: "net",
		doc: "The box's own network. Everything here has to match the LAN it sits on;\n" +
			"a wrong static_ip is a box that never comes up.",
		keys: []entry{
			{"wan_if", "the interface facing the router — the only NIC on a thin client"},
			{"lan_cidr", "the LAN this gateway serves"},
			{"router", "the upstream router; the box's own default route"},
			{"static_ip", "must be OUTSIDE the router's DHCP pool"},
			{"prefix_len", ""},
		},
	},
	{
		name: "ipv6",
		doc: "\"off\" disables IPv6 on the LAN side only. A dual-stacked client would\n" +
			"otherwise get its v6 default route from Router Advertisements and bypass\n" +
			"the tunnel entirely. Tailscale still needs v6 for its own addressing.",
		keys: []entry{{"mode", `"off" or "pass"`}},
	},
	{
		name: "policy",
		doc: "What happens to a device that points its gateway here without being\n" +
			"listed below. This is the setting that makes opting in a one-line change\n" +
			"on the device and nothing here.",
		keys: []entry{{"default", `"proxy", "direct", "block", or a profile name`}},
	},
	{
		name:  "client",
		array: true,
		doc: "Per-device overrides. A device only needs listing to differ from the\n" +
			"default; anything unlisted gets [policy].default. Listed devices need a\n" +
			"static IP or a DHCP reservation, because the override is keyed to it.",
		keys: []entry{{"ip", ""}, {"name", ""}, {"policy", ""}},
	},
	{
		name: "xray",
		doc:  "The tunnel. Ports are loopback-only except tproxy_port, which nftables feeds.",
		keys: []entry{
			{"tproxy_port", ""},
			{"socks_port", "loopback SOCKS, for probes and `gw bench`"},
			{"http_port", ""},
			{"api_port", "loopback stats API — how `gw check` proves which path a flow took"},
			{"log_level", ""},
			{"domain_strategy", ""},
			{"outbound_mark", "the loop guard: every outbound carries it, and the firewall exempts it"},
		},
	},
	{
		name: "xray.outbound",
		doc: "The main server, as a complete Xray outbound object used verbatim.\n" +
			"The gateway models no protocols or transports — anything Xray supports\n" +
			"works. Set exactly one of `file` or `json`.",
		keys: []entry{
			{"file", "path to a .json outbound, relative to this file"},
			{"json", "or the outbound inline"},
			{"server_ip", "pin the address to skip DNS at boot"},
			{"server_domain", "override the address used for DNS pinning"},
		},
	},
	{
		name: "xray.fallback",
		doc:  "A second server. When enabled, Xray load-balances by observed latency.",
		keys: []entry{{"enabled", ""}, {"file", ""}, {"json", ""}, {"server_ip", ""}},
	},
	{
		name:  "upstream",
		array: true,
		doc: "Extra servers that profiles can route selected traffic through — a work\n" +
			"VPN, a second exit country. Each is a complete Xray outbound, like the\n" +
			"main one.",
		keys: []entry{{"name", ""}, {"file", ""}, {"json", ""}, {"server_ip", ""}},
	},
	{
		name:  "profile",
		array: true,
		doc: "A built-in policy plus destination-specific exceptions: \"behave like\n" +
			"`base`, except send these domains or networks via X\".\n" +
			"\n" +
			"A profile device is ALWAYS intercepted, even with base = \"direct\":\n" +
			"splitting traffic by destination requires Xray to see it. So it is\n" +
			"fail-closed like any proxied device.",
		keys: []entry{{"name", ""}, {"base", `"proxy" or "direct"`}},
	},
	{
		name:  "route",
		array: true,
		doc: "Extra Xray routing rules spliced into the generated pipeline. The table\n" +
			"IS the rule — every key but `position` is passed to Xray as written.\n" +
			"\n" +
			"position: \"first\"  ahead of everything, including per-client policy\n" +
			"          \"before\" after per-client policy, ahead of the geo split (default)\n" +
			"          \"after\"  after the geo split, before the fallthrough defaults",
		keys: []entry{{"position", ""}, {"outboundTag", ""}},
	},
	{
		name: "routing",
		doc:  "The global split: what goes direct rather than through the tunnel.",
		keys: []entry{
			{"direct_geosite", "domains that bypass the tunnel"},
			{"direct_geoip", "networks that bypass the tunnel"},
			{"block_geosite", "domains dropped outright, for every client"},
			{"block_geoip", "networks dropped outright, for every client"},
			{"block_bittorrent", ""},
			{"extra_local_networks", "private ranges genuinely reachable here, beyond this LAN"},
			{"drop_private_destinations",
				"drop RFC1918 destinations that are not reachable here. A filtering\n" +
					"resolver answers a blocked name with a private address; without this\n" +
					"the client's traffic goes there, is never intercepted, and dies with\n" +
					"no counter and no log."},
		},
	},
	{
		name: "dns",
		doc: "AdGuard Home serves the LAN. Its upstream DoH is captured by the output\n" +
			"chain like any other local process, so it resolves through the tunnel.",
		keys: []entry{
			{"adguard_port", ""},
			{"adguard_ui_port", ""},
			{"upstreams_proxied",
				"DoH, over the tunnel. Must be IP literals: a hostname here would need\n" +
					"DNS to resolve the DNS server, which cannot work at boot."},
			{"upstreams_direct", "plain resolvers for domestic names, reached directly"},
			{"direct_suffixes", "suffixes routed to upstreams_direct"},
			{"bootstrap", ""},
			{"intercept", "redirect plain DNS from LAN clients to AdGuard, whatever they chose"},
			{"blocklists", ""},
			{"querylog_days", ""},
			{"statslog_days", ""},
		},
	},
	{
		name: "tailscale",
		doc:  "Subnet router and exit node.",
		keys: []entry{
			{"enabled", ""},
			{"ssh", ""},
			{"exit_node", ""},
			{"subnet_router", ""},
			{"exit_node_policy",
				"how exit-node traffic is routed: any policy or profile name, so a\n" +
					"phone abroad can take the same path as a laptop here"},
			{"route_control_via_xray", "tunnel tailscaled's own control-plane traffic"},
			{"lifeline_after_min",
				"if the tunnel stays down this long, let tailscaled talk direct so you\n" +
					"do not lose remote access exactly when you need it. Client traffic\n" +
					"stays fail-closed regardless."},
		},
	},
	{
		name: "web",
		doc: "The dashboard. It can rewrite the firewall and schedule root jobs, so it\n" +
			"is fenced by source address, a password, a CSRF token and privilege\n" +
			"separation. Never widen allow_cidrs to 0.0.0.0/0 — the loader refuses it.",
		keys: []entry{
			{"enabled", ""},
			{"listen", ""},
			{"port", ""},
			{"tls", ""},
			{"cert", ""},
			{"key", ""},
			{"allow_cidrs", "who may reach it at all; defaults to this LAN plus the tailnet"},
			{"session_hours", ""},
			{"max_failed_logins", ""},
			{"lockout_minutes", ""},
		},
	},
	{
		name: "health",
		doc: "The watchdog. It probes the path a client's traffic actually takes, not a\n" +
			"SOCKS shortcut — a probe that cannot see the failure is worse than none.",
		keys: []entry{
			{"interval_sec", ""},
			{"probe_url", ""},
			{"probe_timeout_sec", ""},
			{"domestic_probe_url", ""},
			{"restart_after_fails", "consecutive failures before Xray is restarted"},
			{"fallback_after_fails", "and before the Tailscale lifeline engages"},
		},
	},
	{
		name: "performance",
		doc: "Left mostly unset on purpose: picking these without measuring the\n" +
			"specific link is how you make things slower while believing you tuned them.",
		keys: []entry{
			{"buffer_size_kb", "-1 leaves Xray's own default alone"},
			{"tcp_congestion", "bbr helps most on a lossy path, which a censored route usually is"},
			{"tcp_no_delay", ""},
			{"conn_idle_sec", ""},
		},
	},
	{
		name: "geodata",
		doc:  "Routing data. Every .dat in the latest release is pulled unless `files` pins the set.",
		keys: []entry{
			{"repo", ""},
			{"url_template", "{0} is replaced with each file name"},
			{"files", "empty means whatever the release ships"},
			{"min_bytes", "a truncated .dat takes the tunnel down, and this runs unattended"},
		},
	},
	{
		name: "bootstrap",
		doc: "Only for the setup and update paths, before the tunnel exists. Once the\n" +
			"gateway is running its own traffic is already proxied and this is unused.",
		keys: []entry{{"socks_proxy", "prefer socks5h:// so DNS is resolved at the proxy"}},
	},
	{
		name: "system",
		doc:  "The box itself.",
		keys: []entry{
			{"timezone", ""},
			{"journal_max_use", ""},
			{"zram", ""},
			{"bbr", ""},
			{"unattended_upgrades", ""},
			{"auto_update", `"off", "check", "services" (the default) or "all"`},
			{"auto_update_schedule", "any systemd OnCalendar; validated before it is installed"},
			{"ssh_allow_lan", ""},
			{"ssh_allow_tailnet", ""},
		},
	},
	{
		name:  "job",
		array: true,
		doc: "Scheduled bash. Stored here so a rebuilt box comes back with its jobs.\n" +
			"\n" +
			"Jobs run as root unless `user` says otherwise, which makes the dashboard\n" +
			"password a root password.",
		keys: []entry{{"name", ""}, {"schedule", ""}, {"user", ""}, {"enabled", ""},
			{"description", ""}, {"script", ""}},
	},
}
