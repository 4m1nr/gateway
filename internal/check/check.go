// Package check verifies the whole gateway end to end.
//
// "It works right now" and "it comes back after a power cut" are different
// claims, and so are "the tunnel is up" and "traffic is actually going through
// it". This checks each of them separately, because every one of them has been
// wrong at some point while the others looked fine.
package check

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/system"
)

// Status is one check's outcome.
type Status string

const (
	Pass Status = "pass"
	Fail Status = "fail"
	// Skip means the check could not run — a tool is missing, or the component
	// is not installed. Deliberately distinct from Pass: "we did not look" must
	// never read as "we looked and it was fine".
	Skip Status = "skip"
)

// Result is one check.
type Result struct {
	Status Status `json:"status"`
	// Message is the one-line verdict.
	Message string `json:"message"`
	// Detail is what to do about it, shown only on failure.
	Detail string `json:"detail,omitempty"`
}

// Section groups related checks.
type Section struct {
	Name    string   `json:"name"`
	Results []Result `json:"results"`
}

// Report is the whole run.
type Report struct {
	Sections []Section `json:"sections"`
	Passed   int       `json:"passed"`
	Failed   int       `json:"failed"`
	Skipped  int       `json:"skipped"`
}

// OK reports whether everything that ran, passed.
func (r Report) OK() bool { return r.Failed == 0 }

// Runner performs the checks.
type Runner struct {
	// Env is the rendered settings file, already parsed.
	Env map[string]string
	// Systemd talks to init.
	Systemd system.Systemd
	// Killswitch additionally stops Xray to prove that proxied traffic dies
	// rather than leaking. It causes a brief outage, so it is opt-in.
	Killswitch bool

	report  Report
	section *Section
}

func (r *Runner) sec(name string) {
	r.report.Sections = append(r.report.Sections, Section{Name: name})
	r.section = &r.report.Sections[len(r.report.Sections)-1]
}

func (r *Runner) add(status Status, detail string, format string, a ...any) {
	res := Result{Status: status, Message: fmt.Sprintf(format, a...), Detail: detail}
	r.section.Results = append(r.section.Results, res)
	switch status {
	case Pass:
		r.report.Passed++
	case Fail:
		r.report.Failed++
	case Skip:
		r.report.Skipped++
	}
}

func (r *Runner) ok(format string, a ...any)   { r.add(Pass, "", format, a...) }
func (r *Runner) skip(format string, a ...any) { r.add(Skip, "", format, a...) }
func (r *Runner) bad(format string, a ...any)  { r.add(Fail, "", format, a...) }

// badf records a failure with guidance on what to do next.
func (r *Runner) badf(detail, format string, a ...any) { r.add(Fail, detail, format, a...) }

// verdict records pass or fail from a boolean, which keeps the common shape to
// one line.
func (r *Runner) verdict(good bool, pass, fail string) {
	if good {
		r.ok("%s", pass)
		return
	}
	r.bad("%s", fail)
}

func (r Runner) env(key, fallback string) string {
	if v := r.Env[key]; v != "" {
		return v
	}
	return fallback
}

// Run performs every check, in the order a packet meets the system.
func (r *Runner) Run() Report {
	r.checkServices()
	r.checkBoot()
	r.checkPlumbing()
	r.checkDefaultPolicy()
	r.checkEgress()
	r.checkSplitRouting()
	r.checkDNS()
	r.checkIPv6()
	r.checkDashboard()
	r.checkTailscale()
	if r.Killswitch {
		r.checkKillswitch()
	}
	return r.report
}

// -------------------------------------------------------------- services --

func (r *Runner) checkServices() {
	r.sec("services")
	sd := r.Systemd.Querying()
	for _, unit := range []string{"gw-network", "xray", "AdGuardHome", "tailscaled"} {
		if !sd.Exists(unit + ".service") {
			r.skip("%s not installed", unit)
			continue
		}
		if state := sd.IsActive(unit + ".service"); state == "active" {
			r.ok("%s active", unit)
		} else {
			r.bad("%s is %s", unit, state)
		}
	}
}

// ------------------------------------------------------------------ boot --

func (r *Runner) checkBoot() {
	r.sec("boot")
	sd := r.Systemd.Querying()

	// "It works right now" and "it comes back after a power cut" are different
	// claims. This is the second one.
	for _, unit := range []string{"gateway.target", "gw-network.service", "xray.service",
		"gw-health.timer", "gw-geoupdate.timer"} {
		if !sd.Exists(unit) {
			r.bad("%s is not installed", unit)
			continue
		}
		if sd.IsEnabled(unit) == "enabled" {
			r.ok("%s enabled at boot", unit)
		} else {
			r.badf("run: sudo gw enable",
				"%s is NOT enabled — it will not come back after a reboot", unit)
		}
	}
	for _, unit := range []string{"AdGuardHome.service", "tailscaled.service", "chrony-wait.service"} {
		if !sd.Exists(unit) {
			r.skip("%s not installed", unit)
			continue
		}
		if state := sd.IsEnabled(unit); state == "enabled" || state == "enabled-runtime" ||
			state == "static" || state == "indirect" {
			r.ok("%s enabled at boot", unit)
		} else {
			r.bad("%s is NOT enabled at boot", unit)
		}
	}
}

// -------------------------------------------------------------- plumbing --

func (r *Runner) checkPlumbing() {
	r.sec("plumbing")
	sd := r.Systemd.Querying()

	r.verdict(nftTableLoaded(),
		"nftables table loaded",
		"nftables table inet gateway is NOT loaded — nothing is intercepted")

	// Two units managing one ruleset is a silent, intermittent failure: the
	// table disappears while gw-network still reports active.
	competing := sd.Exists("nftables.service") &&
		!strings.Contains(sd.IsEnabled("nftables.service"), "masked") &&
		sd.IsEnabled("nftables.service") == "enabled"
	r.verdict(!competing,
		"nftables.service is not competing for the ruleset",
		"nftables.service is enabled — it flushes the ruleset and will erase the gateway table")

	r.verdict(readSysctl("/proc/sys/net/ipv4/ip_forward") == "1",
		"IPv4 forwarding on",
		"net.ipv4.ip_forward is 0 — direct-policy clients cannot reach anything")

	// Tailscale checks IPv6 as well: --advertise-exit-node advertises ::/0
	// alongside 0.0.0.0/0, so v6 forwarding being off is enough on its own to
	// have Tailscale report "IP forwarding is disabled" on a box that forwards
	// IPv4 perfectly well — and the wording sends you to the knob that is fine.
	switch readSysctl("/proc/sys/net/ipv6/conf/all/forwarding") {
	case "1":
		r.ok("IPv6 forwarding on (Tailscale checks it even with IPv6 off on the LAN)")
	case "":
		r.skip("IPv6 is compiled out of this kernel")
	default:
		r.bad("net.ipv6.conf.all.forwarding is 0 — Tailscale will report " +
			"'IP forwarding is disabled'")
	}

	table := r.env("RT_TABLE", "100")
	rules, _ := runOut(5*time.Second, "ip", "rule", "list")
	r.verdict(strings.Contains(rules, "lookup "+table),
		"fwmark policy rule present",
		"no fwmark rule — TPROXY packets will not be delivered locally")

	routes, _ := runOut(5*time.Second, "ip", "route", "show", "table", table)
	r.verdict(strings.Contains(routes, "local default dev lo"),
		"local default route in table "+table,
		"table "+table+" has no 'local default dev lo' route")

	tproxyPort := r.env("TPROXY_PORT", "12345")
	r.verdict(listening(tproxyPort),
		"Xray is listening on the TPROXY port ("+tproxyPort+")",
		"nothing listening on "+tproxyPort)

	r.checkClock()
}

// checkClock verifies the system time.
//
// The clock is load-bearing: TLS and REALITY both fail on skew, and the symptom
// looks like a broken tunnel rather than a wrong time. Thin clients often have
// a flat CMOS battery and boot years out of date.
func (r *Runner) checkClock() {
	if _, err := exec.LookPath("chronyc"); err != nil {
		r.skip("chrony not available")
		return
	}
	out, err := runOut(10*time.Second, "chronyc", "tracking")
	if err != nil {
		r.skip("chrony not available")
		return
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "System time") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			break
		}
		var offset float64
		if _, err := fmt.Sscanf(fields[3], "%g", &offset); err != nil {
			break
		}
		if offset < 2 {
			r.ok("clock synced (offset %.3fs)", offset)
		} else {
			r.bad("clock is off by %.3fs — TLS will fail", offset)
		}
		return
	}
	r.skip("could not read the clock offset from chronyc")
}

// -------------------------------------------------------- default policy --

func (r *Runner) checkDefaultPolicy() {
	r.sec("default policy")
	policy := r.env("DEFAULT_POLICY", "proxy")
	tproxyPort := r.env("TPROXY_PORT", "12345")

	switch policy {
	case "direct":
		r.ok("default is direct — unlisted devices are forwarded unproxied")
		return
	case "block":
		r.ok("default is block — unlisted devices are dropped")
		return
	}

	pre, _ := runOut(5*time.Second, "nft", "list", "chain", "inet", "gateway", "prerouting")
	// `tproxy ip to :PORT`, not `to 127.0.0.1:PORT`. Rewriting the destination
	// to loopback makes the packet a martian on a real interface and the kernel
	// drops it.
	r.verdict(strings.Contains(pre, "tproxy ip to :"+tproxyPort),
		"unlisted devices pointing here are intercepted by default",
		"no catch-all TPROXY rule — an unlisted device would just be dropped")

	fwd, _ := runOut(5*time.Second, "nft", "list", "chain", "inet", "gateway", "forward")
	r.verdict(strings.Contains(fwd, "killswitch-default"),
		"catch-all kill switch present",
		"no catch-all kill switch — unlisted devices could leak if Xray dies")
}

// ---------------------------------------------------------------- egress --

// probeURL answers with the caller's public address, which is how the three
// egress paths are told apart.
const probeURL = "https://api.ipify.org"

func (r *Runner) checkEgress() {
	r.sec("egress")
	socks := r.env("SOCKS_PORT", "10808")

	// The path a client's traffic actually takes: no SOCKS shortcut, so this
	// exercises output marking, policy routing, prerouting interception and
	// Xray. Deliberately not proxied.
	intercepted, _ := curl(25*time.Second, "", probeURL)

	// Anything running as the xray user bypasses the tunnel — the output chain
	// returns early on that uid — which gives the box's real address for free.
	real, realErr := system.RunAsUser("xray", 20*time.Second, "curl", "-fsS",
		"--max-time", "15", probeURL)
	real = strings.TrimSpace(real)

	tunnel, _ := curl(25*time.Second, socks, probeURL)

	switch {
	case real != "":
		r.ok("direct egress works (ISP address: %s)", real)
	case realErr != nil && strings.Contains(realErr.Error(), "no such user"):
		r.skip("cannot run as the xray user — direct-egress comparison unavailable")
	default:
		r.bad("no direct egress — the box cannot reach the internet at all")
	}

	r.verdict(tunnel != "",
		"tunnel egress works (exit address: "+tunnel+")",
		"tunnel egress FAILED — check 'journalctl -u xray -n 50'")

	if real != "" && tunnel != "" {
		r.verdict(real != tunnel,
			"tunnel egress differs from the ISP address",
			"tunnel and direct show the SAME address — traffic is not being proxied")
	}

	// This is the one that matters. SOCKS working while this fails means Xray
	// is healthy and the packets are not reaching it — the failure mode that
	// reported "tunnel UP" through two separate outages.
	switch {
	case intercepted == "":
		r.badf("Check: nft list chain inet gateway prerouting (the 'iif lo' tproxy rule\n"+
			"must precede 'iif lo return'), and 'ip rule list' for the fwmark rule.",
			"intercepted egress FAILED — a plain request from this box does not reach the tunnel")
	case tunnel != "" && intercepted == tunnel:
		r.ok("intercepted egress leaves via the tunnel (%s)", intercepted)
	case real != "" && intercepted == real:
		r.bad("intercepted egress leaves via the ISP (%s) — traffic is escaping the tunnel",
			intercepted)
	default:
		r.ok("intercepted egress works (%s)", intercepted)
	}
}

// --------------------------------------------------------- split routing --

func (r *Runner) checkSplitRouting() {
	r.sec("split routing")
	if _, err := exec.LookPath("xray"); err != nil {
		r.skip("Xray stats API unreachable — cannot verify the split")
		return
	}
	apiPort := r.env("API_PORT", "10085")
	if _, err := statsQuery(apiPort); err != nil {
		r.skip("Xray stats API unreachable — cannot verify the split")
		return
	}
	socks := r.env("SOCKS_PORT", "10808")

	// Ask which outbound each request actually used, rather than inferring it.
	beforeProxy := counter(apiPort, "outbound>>>proxy>>>traffic>>>uplink")
	beforeDirect := counter(apiPort, "outbound>>>direct>>>traffic>>>uplink")
	_, _ = curl(25*time.Second, socks, r.env("DOMESTIC_PROBE_URL", "https://www.irna.ir"))
	deltaProxy := counter(apiPort, "outbound>>>proxy>>>traffic>>>uplink") - beforeProxy
	deltaDirect := counter(apiPort, "outbound>>>direct>>>traffic>>>uplink") - beforeDirect

	switch {
	case deltaDirect > deltaProxy:
		r.ok("domestic request went DIRECT (direct +%dB vs proxy +%dB)", deltaDirect, deltaProxy)
	case deltaProxy > 0:
		r.bad("domestic request went through the TUNNEL (proxy +%dB) — check geodata "+
			"and the direct_geosite rules", deltaProxy)
	default:
		r.skip("domestic probe produced no traffic (site unreachable?)")
	}

	beforeProxy = counter(apiPort, "outbound>>>proxy>>>traffic>>>uplink")
	_, _ = curl(25*time.Second, socks, "https://www.google.com")
	r.verdict(counter(apiPort, "outbound>>>proxy>>>traffic>>>uplink") > beforeProxy,
		"foreign request went through the tunnel",
		"foreign request did not use the proxy outbound")
}

// ------------------------------------------------------------------- dns --

func (r *Runner) checkDNS() {
	r.sec("dns")
	boxIP := r.Env["BOX_IP"]

	r.verdict(resolvesLocally("example.com"),
		"the box resolves names",
		"the box cannot resolve — is AdGuard running?")

	if _, err := exec.LookPath("dig"); err != nil {
		r.skip("dig not installed")
		return
	}
	if boxIP == "" {
		r.skip("no box address is known — has `gw apply` run?")
		return
	}

	r.verdict(digAnswers(boxIP, "example.com"),
		"AdGuard answers on "+boxIP+":53",
		"no answer from "+boxIP+":53 — LAN clients will have no DNS")
	r.verdict(digAnswers(boxIP, "irna.ir"),
		"domestic names resolve",
		"domestic names do not resolve — check the [/ir/] upstream split")

	// Poisoning canary. A public name answering with private or reserved space
	// is a filtering resolver, not a real answer — and it is quiet, because
	// that address sits in bypass_dst, so the connection is never intercepted
	// and fails mid-TLS-handshake looking like a broken tunnel instead of bad
	// DNS.
	var poisoned []string
	for _, name := range []string{"www.google.com", "cloudflare.com", "github.com"} {
		for _, addr := range digA(boxIP, name) {
			if isPrivateOrReserved(addr) {
				poisoned = append(poisoned, name+"="+addr)
			}
		}
	}
	if len(poisoned) == 0 {
		r.ok("no DNS poisoning detected (public names resolve to public addresses)")
	} else {
		r.badf("That is a filtering resolver. Check AdGuard's upstreams — fallback_dns\n"+
			"must not point at a resolver that lies.",
			"DNS is returning private addresses for public names: %s",
			strings.Join(poisoned, " "))
	}
}

// ------------------------------------------------------------------ ipv6 --

func (r *Runner) checkIPv6() {
	r.sec("ipv6")
	wan := r.Env["WAN_IF"]
	if wan == "" {
		r.skip("no WAN interface is known — has `gw apply` run?")
		return
	}

	out, _ := runOut(5*time.Second, "ip", "-6", "addr", "show", "dev", wan, "scope", "global")
	r.verdict(!strings.Contains(out, "inet6"),
		wan+" has no global IPv6 address",
		wan+" has a global IPv6 address — clients can bypass the tunnel over v6")

	// A working v6 path is an unproxied path. The check passes when it fails.
	_, err := runOut(8*time.Second, "curl", "-6", "-fsS", "--max-time", "5",
		"https://api64.ipify.org")
	r.verdict(err != nil,
		"no IPv6 egress",
		"the box has working IPv6 egress — that path is not proxied")
}

// ------------------------------------------------------------ killswitch --

// checkKillswitch proves that proxied traffic dies rather than leaking.
//
// It stops Xray, which cuts every proxied client off for a few seconds. That is
// the whole point — a kill switch nobody has tested is a belief, not a
// guarantee — but it is why this is opt-in.
func (r *Runner) checkKillswitch() {
	r.sec("killswitch (this briefly cuts proxied clients off)")
	tproxyPort := r.env("TPROXY_PORT", "12345")

	before := killswitchDrops()
	if err := r.Systemd.Stop("xray.service"); err != nil {
		r.bad("could not stop Xray to test the killswitch: %v", err)
		return
	}
	// Restarting is deferred so an early return cannot leave the gateway down.
	defer func() {
		if err := r.Systemd.Start("xray.service"); err != nil {
			r.bad("Xray did not come back: %v", err)
			return
		}
		time.Sleep(3 * time.Second)
		r.verdict(r.Systemd.Querying().IsActive("xray.service") == "active",
			"Xray restarted", "Xray did not come back")
	}()

	time.Sleep(2 * time.Second)
	r.verdict(!listening(tproxyPort),
		"Xray stopped, TPROXY listener gone",
		"something is still listening on "+tproxyPort+" after stopping Xray")

	// With no listener, an intercepted client's packets fall through to the
	// terminal drop instead of finding a direct path out.
	fwd, _ := runOut(5*time.Second, "nft", "list", "chain", "inet", "gateway", "forward")
	r.verdict(strings.Contains(fwd, "killswitch"),
		fmt.Sprintf("killswitch drop rule is in place (drops so far: %d)", before),
		"no killswitch rule in the forward chain — traffic could leak")
}

// --------------------------------------------------------------- helpers --

func runOut(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

func nftTableLoaded() bool {
	_, err := runOut(5*time.Second, "nft", "list", "table", "inet", "gateway")
	return err == nil
}

func readSysctl(path string) string {
	out, err := runOut(2*time.Second, "cat", path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func listening(port string) bool {
	out, err := runOut(5*time.Second, "ss", "-lnt", "sport = :"+port)
	return err == nil && strings.Contains(out, port)
}

// curl fetches a URL, optionally through the local SOCKS inbound.
func curl(timeout time.Duration, socksPort, url string) (string, error) {
	args := []string{"-fsS", "--max-time", fmt.Sprintf("%d", int(timeout.Seconds())-5)}
	if socksPort != "" {
		args = append(args, "--socks5-hostname", "127.0.0.1:"+socksPort)
	}
	args = append(args, url)
	out, err := runOut(timeout, "curl", args...)
	return strings.TrimSpace(out), err
}
