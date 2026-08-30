// Package fixtures derives the test configs from gateway.example.toml.
//
// Fixtures are generated, not hand-maintained. When the example config changes,
// a stale fixture silently stops exercising the thing it was written for: a
// replacement that no longer matches leaves the default in place, and the test
// goes on passing while testing nothing.
package fixtures

import (
	"fmt"
	"regexp"
	"strings"
)

// Fixture is one generated config.
type Fixture struct {
	Name string
	Body string
}

// clientBlockRE matches the example's illustrative [[client]] entries.
var clientBlockRE = regexp.MustCompile(
	`\[\[client\]\]\nip     = "192\.168\.1\.(60|99)"\nname   = "[^"]+"\npolicy = "[\w-]+"\n\n?`)

// Build derives every fixture from the example config.
//
// Each substitution is checked: a pattern that no longer appears is an error
// rather than a silent no-op, because the resulting fixture would look valid
// and test the default instead of the case it was named for.
func Build(example string) ([]Fixture, error) {
	b := &builder{example: example}

	b.add("default", example)

	b.derive("ipv6-pass-no-clients", example, func(t string) string {
		t = b.sub(t, `mode = "off"`, `mode = "pass"`)
		t = clientBlockRE.ReplaceAllString(t, "")
		return b.sub(t, "route_control_via_xray = true", "route_control_via_xray = false")
	})

	b.derive("reality-fallback", example, func(t string) string {
		t = b.sub(t, `file = "outbounds/main.json"`, `file = "outbounds/reality.json"`)
		t = b.sub(t, "block_bittorrent = false", "block_bittorrent = true")
		t = b.sub(t, "block_geosite  = []", `block_geosite  = ["geosite:category-ads-all"]`)
		t = b.sub(t, "block_geoip    = []", `block_geoip    = ["geoip:cn", "198.51.100.0/24"]`)
		return b.sub(t, `[xray.fallback]
enabled = false
# file      = "outbounds/backup.json"
# server_ip = ""`, `[xray.fallback]
enabled = true
file    = "outbounds/backup.json"`)
	})

	b.derive("no-tailscale", example, func(t string) string {
		t = b.sub(t, "enabled        = true", "enabled        = false")
		return b.sub(t, `server_ip = ""`, `server_ip = "203.0.113.10"`)
	})

	for _, policy := range []string{"direct", "block"} {
		b.derive("default-policy-"+policy, example, func(t string) string {
			return b.subRE(t, regexp.MustCompile(`(?m)^default = "proxy"$`),
				fmt.Sprintf(`default = %q`, policy))
		})
	}

	b.derive("no-web", example, func(t string) string {
		// Only the first: [web] is the first table with a bare `enabled`.
		return b.subFirstRE(t, regexp.MustCompile(`(?m)^enabled = true$`), "enabled = false")
	})

	b.derive("trojan-upstream", example, func(t string) string {
		return b.sub(t, `file = "outbounds/main.json"`, `file = "outbounds/trojan.json"`)
	})

	// Exercises the bootstrap proxy and, at the same time, the other geodata
	// shape: two sources, one pinned to specific files through a mirror.
	b.derive("bootstrap-proxy", example, func(t string) string {
		t = b.sub(t, `socks_proxy = ""`, `socks_proxy = "socks5h://127.0.0.1:1080"`)
		return b.sub(t, `[[geodata.source]]
name = "iran"
repo = "Chocolate4U/Iran-v2ray-rules"`, `[[geodata.source]]
name = "iran"
repo = "Chocolate4U/Iran-v2ray-rules"

[[geodata.source]]
name         = "mirror"
files        = ["geoip", "geosite"]
url_template = "https://mirror.example.com/v2ray/{0}.dat"

[[geodata.source]]
name    = "parked"
enabled = false
files        = ["geoip"]
url_template = "https://parked.example.com/{0}.dat"`)
	})

	profiles := example + profilesSuffix
	b.add("profiles", profiles)

	b.derive("exit-node-profile", profiles, func(t string) string {
		return b.sub(t, `exit_node_policy = "proxy"`, `exit_node_policy = "work-laptop"`)
	})
	b.derive("exit-node-direct", profiles, func(t string) string {
		return b.sub(t, `exit_node_policy = "proxy"`, `exit_node_policy = "direct"`)
	})

	b.add("custom-routes", profiles+customRoutesSuffix)
	b.add("jobs", example+jobsSuffix())

	if b.err != nil {
		return nil, b.err
	}
	return b.out, nil
}

// builder accumulates fixtures and the first error.
type builder struct {
	example string
	out     []Fixture
	err     error
}

func (b *builder) add(name, body string) {
	b.out = append(b.out, Fixture{Name: name, Body: body})
}

// derive builds a fixture and asserts it actually differs from its base.
func (b *builder) derive(name, base string, fn func(string) string) {
	body := fn(base)
	if b.err == nil && body == base {
		b.err = fmt.Errorf("fixture %s is identical to its base — a replacement missed", name)
		return
	}
	b.add(name, body)
}

func (b *builder) sub(text, old, new string) string {
	if !strings.Contains(text, old) {
		if b.err == nil {
			b.err = fmt.Errorf("pattern not found in the example config:\n  %q", old)
		}
		return text
	}
	// Every occurrence, matching what the Python generator did. Some anchors
	// appear twice — once live and once in a commented example beside it — and
	// replacing only the first leaves the comment contradicting the setting
	// just above it.
	return strings.ReplaceAll(text, old, new)
}

func (b *builder) subRE(text string, re *regexp.Regexp, replacement string) string {
	if !re.MatchString(text) {
		if b.err == nil {
			b.err = fmt.Errorf("pattern not found in the example config: %s", re)
		}
		return text
	}
	return re.ReplaceAllString(text, replacement)
}

func (b *builder) subFirstRE(text string, re *regexp.Regexp, replacement string) string {
	loc := re.FindStringIndex(text)
	if loc == nil {
		if b.err == nil {
			b.err = fmt.Errorf("pattern not found in the example config: %s", re)
		}
		return text
	}
	return text[:loc[0]] + replacement + text[loc[1]:]
}

const profilesSuffix = `
[[upstream]]
name     = "work"
file     = "outbounds/work.json"
location = "outside"
# Inside 10.20.0.0/16 below, which the profile already routes here. nftables
# rejects overlapping intervals outright, so this shape has to stay covered.
dns      = "10.20.0.53"

[[profile]]
name = "work-laptop"
base = "proxy"

  [[profile.route]]
  via     = "work"
  domains = ["domain:corp.work-example.com"]
  ips     = ["10.20.0.0/16", "203.0.113.0/24"]

  [[profile.route]]
  via     = "block"
  domains = ["geosite:category-ads-all"]

[[profile]]
name = "mostly-local"
base = "direct"

  [[profile.route]]
  via = "work"
  ips = ["10.20.0.0/16"]

  [[profile.route]]
  via     = "proxy"
  domains = ["domain:news.example.com"]

[[client]]
ip     = "192.168.1.70"
name   = "work-laptop"
policy = "work-laptop"

[[client]]
ip     = "192.168.1.71"
name   = "desktop"
policy = "mostly-local"
`

const customRoutesSuffix = `
[[route]]
position    = "first"
ip          = ["203.0.113.5/32"]
port        = "22"
outboundTag = "block"

[[route]]
domain      = ["domain:intranet.example.com"]
outboundTag = "direct"

[[route]]
ip          = ["198.51.100.0/24"]
outboundTag = "work"

[[route]]
position    = "after"
port        = "5353"
network     = "udp"
outboundTag = "direct"

[[route]]
position = "first"
json     = """
{ "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }
"""
`

// jobsSuffix builds the scheduled-job fixtures.
//
// The TOML literal-string quote is spliced in rather than written inline, so
// this file does not have to nest triple quotes — and so the bash below, which
// contains %, $() and backslash continuations, survives verbatim. Those are the
// exact characters naive storage mangles, which is what the fixture is for.
func jobsSuffix() string {
	q := strings.Repeat("'", 3)
	return strings.ReplaceAll(`
[[job]]
name        = "backup-config"
description = "Copy the AdGuard config somewhere safe"
schedule    = "0 4 * * *"
script      = @Q@
install -d /var/backups/gateway
cp -a /opt/AdGuardHome/AdGuardHome.yaml \
      /var/backups/gateway/AdGuardHome-$(date +%F).yaml
find /var/backups/gateway -name 'AdGuardHome-*.yaml' -mtime +14 -delete
@Q@

[[job]]
name        = "speedtest"
description = "Log throughput through the tunnel"
schedule    = "@hourly"
user        = "nobody"
script      = @Q@
curl -o /dev/null -s -w 'down %{speed_download} B/s\n' \
     --socks5-hostname 127.0.0.1:10808 \
     https://speed.cloudflare.com/__down?bytes=10000000
@Q@

[[job]]
name     = "parked"
schedule = "@weekly"
enabled  = false
script   = "echo this one is disabled"
`, "@Q@", q)
}
