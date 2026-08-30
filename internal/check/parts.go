package check

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ------------------------------------------------------------- dashboard --

// webSettings is /etc/gateway/web.json, as rendered.
type webSettings struct {
	Port       int      `json:"port"`
	TLS        bool     `json:"tls"`
	AllowCIDRs []string `json:"allow_cidrs"`
}

// actionHelper is the dashboard's entire privilege surface.
const actionHelper = "/usr/local/lib/gateway/gw-action"

func (r *Runner) checkDashboard() {
	r.sec("web dashboard")

	raw, err := os.ReadFile("/etc/gateway/web.json")
	if err != nil {
		r.skip("dashboard not installed")
		return
	}
	var settings webSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		r.bad("/etc/gateway/web.json is not valid JSON: %v", err)
		return
	}

	r.verdict(r.Systemd.Querying().IsActive("gw-web.service") == "active",
		"gw-web is running", "gw-web is not running")

	// The hash must be unreadable by the web process. That is the whole reason
	// logins are verified across the sudo boundary.
	if info, err := os.Stat("/etc/gateway/web-auth.json"); err != nil {
		r.badf("run: sudo gw web-passwd",
			"no dashboard password set — every login will fail")
	} else {
		owner := fileOwner("/etc/gateway/web-auth.json")
		if info.Mode().Perm() == 0o600 && owner == "root:root" {
			r.ok("password hash is 0600 root:root (the web process cannot read it)")
		} else {
			r.bad("password hash is %04o %s — expected 0600 root:root",
				info.Mode().Perm(), owner)
		}
	}

	// A wildcard here would let the web process choose what it sudoes, which is
	// exactly what the indirection exists to prevent.
	if sudoers, err := os.ReadFile("/etc/sudoers.d/gw-web"); err != nil {
		r.bad("/etc/sudoers.d/gw-web is missing — the dashboard cannot do anything")
	} else {
		r.verdict(!sudoersWildcardRE.Match(sudoers),
			"sudo grant is a single command with no wildcard",
			"/etc/sudoers.d/gw-web contains a wildcard — it should grant exactly one command")
	}

	if owner := fileOwner(actionHelper); owner == "" {
		r.bad("%s is missing — run `sudo gw apply`", actionHelper)
	} else if strings.HasPrefix(owner, "root:") {
		r.ok("the privileged helper is owned by root")
		if info, err := os.Stat(actionHelper); err == nil && info.Mode().Perm()&0o022 != 0 {
			r.bad("%s is writable by group or other (%04o) — gwweb could rewrite "+
				"what it sudoes", actionHelper, info.Mode().Perm())
		}
	} else {
		r.bad("%s is owned by %s — gwweb could rewrite what it sudoes", actionHelper, owner)
	}

	// Gate 1: the port must not be open to the whole world.
	input, err := runOut(5*time.Second, "nft", "list", "chain", "inet", "gateway", "input")
	port := strconv.Itoa(settings.Port)
	switch {
	case err != nil:
		r.skip("could not read the input chain to check the dashboard port")
	case !strings.Contains(input, "dport "+port+" accept"):
		r.bad("no firewall rule for the dashboard port")
	default:
		restricted := false
		for _, line := range strings.Split(input, "\n") {
			if strings.Contains(line, "dport "+port) && strings.Contains(line, "saddr") {
				restricted = true
				break
			}
		}
		r.verdict(restricted,
			"dashboard port "+port+" is restricted by source address",
			"dashboard port "+port+" is accepted from ANY source")
	}

	r.verdict(settings.TLS,
		"dashboard uses TLS",
		"dashboard is plain HTTP — the login password crosses the LAN in clear text")
}

var sudoersWildcardRE = regexp.MustCompile(`NOPASSWD:.*\*`)

// fileOwner returns "user:group", or "" when the file is absent.
func fileOwner(path string) string {
	out, err := runOut(5*time.Second, "stat", "-c", "%U:%G", path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// -------------------------------------------------------------- tailscale --

// tailscaleStatus is the subset of `tailscale status --json` that matters here.
type tailscaleStatus struct {
	Self struct {
		DNSName        string `json:"DNSName"`
		ExitNodeOption bool   `json:"ExitNodeOption"`
	} `json:"Self"`
	Health []string `json:"Health"`
}

func (r *Runner) checkTailscale() {
	r.sec("tailscale")
	if _, err := exec.LookPath("tailscale"); err != nil {
		r.skip("tailscale not set up")
		return
	}
	raw, err := runOut(15*time.Second, "tailscale", "status", "--json")
	if err != nil {
		r.skip("tailscale not set up")
		return
	}
	var status tailscaleStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		r.skip("could not read tailscale status")
		return
	}

	name := strings.TrimSuffix(status.Self.DNSName, ".")
	if name == "" {
		name = "?"
	}
	r.ok("tailscale connected as %s", name)

	if status.Self.ExitNodeOption {
		r.ok("advertised as an exit node")
	} else {
		r.skip("not advertised as an exit node (or not yet approved in the admin console)")
	}

	// Tailscale keeps its own list of what it thinks is wrong with this
	// machine. Surfacing it here means `gw check` cannot pass while Tailscale
	// is telling anyone who looks at the admin console that the box is
	// misconfigured.
	if len(status.Health) == 0 {
		r.ok("tailscale reports no health warnings")
	}
	for _, h := range status.Health {
		r.bad("tailscale: %s", h)
	}

	lifeline := strings.TrimSpace(readFile("/run/gateway/lifeline"))
	r.verdict(lifeline != "1",
		"lifeline not engaged",
		"the lifeline is ENGAGED — tailscaled is bypassing the tunnel because "+
			"it has been down too long")
}

// ------------------------------------------------------------ xray stats --

type statsResponse struct {
	Stat []struct {
		Name  string `json:"name"`
		Value any    `json:"value"`
	} `json:"stat"`
}

func statsQuery(apiPort string) (statsResponse, error) {
	var parsed statsResponse
	out, err := runOut(5*time.Second, "xray", "api", "statsquery",
		"--server=127.0.0.1:"+apiPort)
	if err != nil {
		return parsed, err
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return parsed, fmt.Errorf("the stats API returned something unreadable: %w", err)
	}
	return parsed, nil
}

// counter reads one named counter, or 0.
func counter(apiPort, name string) int64 {
	parsed, err := statsQuery(apiPort)
	if err != nil {
		return 0
	}
	for _, s := range parsed.Stat {
		if s.Name != name {
			continue
		}
		switch v := s.Value.(type) {
		case string:
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		case float64:
			return int64(v)
		}
	}
	return 0
}

// killswitchDrops totals both killswitch rules — listed clients and the LAN
// catch-all. Reporting one understates what the gateway refused.
func killswitchDrops() int64 {
	out, err := runOut(5*time.Second, "nft", "list", "chain", "inet", "gateway", "forward")
	if err != nil {
		return 0
	}
	var total int64
	re := regexp.MustCompile(`packets (\d+)`)
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "killswitch") {
			continue
		}
		if m := re.FindStringSubmatch(line); m != nil {
			n, _ := strconv.ParseInt(m[1], 10, 64)
			total += n
		}
	}
	return total
}

// ------------------------------------------------------------------- dns --

func resolvesLocally(name string) bool {
	addrs, err := net.LookupHost(name)
	return err == nil && len(addrs) > 0
}

func digAnswers(server, name string) bool {
	return len(digA(server, name)) > 0
}

// digA returns the A records a specific server gives for a name.
func digA(server, name string) []string {
	out, err := runOut(10*time.Second, "dig", "+short", "+time=5", "+tries=1",
		"A", name, "@"+server)
	if err != nil {
		return nil
	}
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if _, err := netip.ParseAddr(line); err == nil {
			addrs = append(addrs, line)
		}
	}
	return addrs
}

// isPrivateOrReserved reports whether an answer for a public name is one a
// filtering resolver hands back.
func isPrivateOrReserved(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsUnspecified() ||
		addr.IsLinkLocalUnicast()
}

func readFile(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

// nftChainLoaded reports whether a chain exists in the running ruleset.
func nftChainLoaded(name string) bool {
	_, err := runOut(5*time.Second, "nft", "list", "chain", "inet", "gateway", name)
	return err == nil
}
