package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func fixtures(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoRoot(t), "tests/fixtures/*.toml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixtures found: %v", err)
	}
	return paths
}

// Every shipped fixture must load. These are the configs the renderer's golden
// files are built from, so a fixture that stops loading invalidates all of them.
func TestFixturesLoad(t *testing.T) {
	for _, path := range fixtures(t) {
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		t.Run(name, func(t *testing.T) {
			cfg, err := Load(path)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if cfg.Server == nil {
				t.Fatal("no main outbound was loaded")
			}
			// The loop guard, on every outbound, is the invariant that matters
			// most: an outbound without it makes Xray's own packets eligible
			// for TPROXY and the box deadlocks.
			for _, ob := range cfg.AllOutbounds() {
				assertTaggedAndMarked(t, cfg, ob)
			}
		})
	}
}

func assertTaggedAndMarked(t *testing.T, cfg *Config, ob *Outbound) {
	t.Helper()
	tag, ok := ob.Object.GetString("tag")
	if !ok || tag != ob.Tag {
		t.Errorf("%s: tag is %q, want %q", ob.Origin, tag, ob.Tag)
	}
	stream, ok := ob.Object.GetObject("streamSettings")
	if !ok {
		t.Fatalf("%s: no streamSettings", ob.Origin)
	}
	sock, ok := stream.GetObject("sockopt")
	if !ok {
		t.Fatalf("%s: no streamSettings.sockopt", ob.Origin)
	}
	mark, ok := sock.GetNumber("mark")
	if !ok {
		t.Fatalf("%s: no sockopt.mark — the loop guard is missing", ob.Origin)
	}
	if got := mark.String(); got != itoa(cfg.OutboundMark) {
		t.Errorf("%s: sockopt.mark is %s, want %d", ob.Origin, got, cfg.OutboundMark)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// The invalid/ fixtures exist because each was once accepted and produced a
// broken gateway.
func TestInvalidFixturesRejected(t *testing.T) {
	paths, _ := filepath.Glob(filepath.Join(repoRoot(t), "tests/invalid/*.toml"))
	if len(paths) == 0 {
		t.Skip("no invalid fixtures")
	}
	for _, path := range paths {
		name := strings.TrimSuffix(filepath.Base(path), ".toml")
		t.Run(name, func(t *testing.T) {
			if _, err := Load(path); err == nil {
				t.Fatal("expected the config to be rejected, but it loaded")
			}
		})
	}
}

// minimalBase is the smallest config that loads: everything else in
// gateway.toml has a default. Tests append the table under test to it, so a
// case can set [system] or [web] without colliding with a fixture that already
// declares them.
const minimalBase = `
[net]
wan_if    = "eth0"
lan_cidr  = "192.168.1.0/24"
router    = "192.168.1.1"
static_ip = "192.168.1.2"

[xray.outbound]
file = "main.json"
`

const minimalOutbound = `{
  "protocol": "vless",
  "settings": {"vnext": [{"address": "example.com", "port": 443,
    "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
  "streamSettings": {"network": "xhttp", "security": "tls"}
}`

// loadWith writes a self-contained config in a temp dir and returns the load
// result. The outbound lives beside it so the relative `file` path resolves.
func loadWith(t *testing.T, body string) (*Config, error) {
	t.Helper()
	return loadWithBase(t, minimalBase, body)
}

// loadWithBase is loadWith with the base config swapped, for cases that need to
// replace a table the base already declares.
func loadWithBase(t *testing.T, base, body string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.json"), []byte(minimalOutbound), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "gateway.toml")
	if err := os.WriteFile(path, []byte(base+"\n"+body+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// The minimal base must itself load, or every rejection test below passes for
// the wrong reason.
func TestMinimalBaseLoads(t *testing.T) {
	cfg, err := loadWith(t, "")
	if err != nil {
		t.Fatalf("the minimal base config does not load: %v", err)
	}
	if cfg.DefaultPolicy != "proxy" {
		t.Errorf("default policy is %q, want proxy", cfg.DefaultPolicy)
	}
}

func TestValidationRejects(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{
			"default_policy in the wrong table",
			"[system]\ndefault_policy = \"direct\"",
			"nothing reads it",
		},
		{
			"unknown default policy",
			"[policy]\ndefault = \"nope\"",
			"policy.default must be one of",
		},
		{
			"web allow_cidrs of everything",
			"[web]\nallow_cidrs = [\"0.0.0.0/0\"]",
			"List real networks",
		},
		{
			"profile with no rules",
			"[[profile]]\nname = \"empty\"\nbase = \"proxy\"",
			"has no [[profile.route]] rules",
		},
		{
			"profile base of block",
			"[[profile]]\nname = \"nope\"\nbase = \"block\"\n[[profile.route]]\nvia = \"direct\"\ndomains = [\"a.example\"]",
			"must be 'proxy' or 'direct'",
		},
		{
			"profile named after a builtin",
			"[[profile]]\nname = \"proxy\"\n[[profile.route]]\nvia = \"direct\"\ndomains = [\"a.example\"]",
			"built-in policy name",
		},
		{
			"profile route with no matcher",
			"[[profile]]\nname = \"p\"\n[[profile.route]]\nvia = \"direct\"",
			"matches nothing",
		},
		{
			"profile route to an unknown target",
			"[[profile]]\nname = \"p\"\n[[profile.route]]\nvia = \"ghost\"\ndomains = [\"a.example\"]",
			"is not a known target",
		},
		{
			"custom route with no outboundTag",
			"[[route]]\ndomain = [\"a.example\"]",
			"has no outboundTag",
		},
		{
			"custom route matching nothing",
			"[[route]]\noutboundTag = \"direct\"",
			"matches nothing",
		},
		{
			"custom route with a bad position",
			"[[route]]\nposition = \"middle\"\ndomain = [\"a.example\"]\noutboundTag = \"direct\"",
			"position must be",
		},
		{
			"job schedule with too few fields",
			"[[job]]\nname = \"j\"\nschedule = \"0 4 * *\"\nscript = \"true\"",
			"cron needs 5",
		},
		{
			// The %-guard further down validate_cron is unreachable for a
			// five-field schedule: the field regex rejects % first. The guard
			// that matters for % is in the renderer's crontab line.
			"job schedule containing a percent",
			"[[job]]\nname = \"j\"\nschedule = \"0 4 * * %\"\nscript = \"true\"",
			"characters cron will not accept",
		},
		{
			"job schedule with an unknown shorthand",
			"[[job]]\nname = \"j\"\nschedule = \"@fortnightly\"\nscript = \"true\"",
			"not a known shorthand",
		},
		{
			"empty job script",
			"[[job]]\nname = \"j\"\nschedule = \"@daily\"\nscript = \"  \"",
			"nothing to run",
		},
		{
			"upstream named after a builtin",
			"[[upstream]]\nname = \"direct\"\nfile = \"main.json\"",
			"reserved",
		},
		{
			"dns upstream named by hostname",
			"[dns]\nupstreams_proxied = [\"https://dns.example.com/dns-query\"]",
			"uses a hostname",
		},
		{
			"geodata url_template without a placeholder",
			"[geodata]\nurl_template = \"https://example.com/geoip.dat\"\nrepo = \"\"",
			"must contain {0}",
		},
		{
			"bootstrap proxy without a scheme",
			"[bootstrap]\nsocks_proxy = \"127.0.0.1:1080\"",
			"needs a scheme",
		},
		{
			"fallback_after below restart_after",
			"[health]\nrestart_after_fails = 6\nfallback_after_fails = 3",
			"must be >= health.restart_after_fails",
		},
		{
			"unknown auto_update mode",
			"[system]\nauto_update = \"sometimes\"",
			"system.auto_update must be one of",
		},
		{
			"tailscale exit policy that does not exist",
			"[tailscale]\nexit_node_policy = \"ghost\"",
			"is not a known policy",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadWith(t, tc.body)
			if err == nil {
				t.Fatalf("expected rejection, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}
