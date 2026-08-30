package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/diag"
)

// parseFlags parses a flag set that allows flags and positional arguments in
// any order, and returns the positional ones.
//
// Go's flag package stops at the first non-flag argument, so `gw history 48
// --json` would treat --json as a positional and fail with a usage error that
// says nothing about why. Reordering the arguments first looks simpler and is
// wrong: it separates `--config` from the path that follows it, which is how
// `gw agent geoupdate --config x --check` came to report the config as
// missing. Parsing repeatedly is what handles a flag's value correctly, because
// the flag set is the only thing that knows which flags take one.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		// Everything up to the next flag is positional; resume parsing there.
		next := len(rest)
		for i, a := range rest {
			if len(a) > 1 && a[0] == '-' {
				next = i
				break
			}
		}
		positional = append(positional, rest[:next]...)
		if next == len(rest) {
			return positional, nil
		}
		args = rest[next:]
	}
}

// ------------------------------------------------------------------ diag ----

func cmdDiag(args []string) error {
	cli.NeedRoot("diag")
	fs := flag.NewFlagSet("diag", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	client := ""
	if len(rest) > 0 {
		client = rest[0]
	}

	d, err := diag.Collector{}.CollectDiag(client)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	}
	printDiag(d)
	return nil
}

func printDiag(d diag.Diag) {
	section := func(title string) { fmt.Printf("\n%s\n", cli.Green("== "+title+" ==")) }

	fmt.Printf("%s\n", cli.Green("== ruleset =="))
	printCounters(d.Counters["prerouting"])

	section("input (where intercepted packets are delivered)")
	printCounters(d.Counters["input"])

	section("forward (traffic that was NOT intercepted)")
	printCounters(d.Counters["forward"])

	section("policy routing")
	for _, r := range d.Rules {
		fmt.Printf("  %s\n", r)
	}
	for _, table := range sortedKeys(d.RouteTables) {
		fmt.Printf("  table %s: %s\n", table, d.RouteTables[table])
	}

	section("interception sets")
	for _, set := range []string{"proxy_clients", "direct_clients", "blocked_clients"} {
		fmt.Printf("  %-16s %s\n", set, strings.Join(d.Sets[set], ", "))
	}
	fmt.Printf("  %-16s %s\n", "default", d.DefaultPolicy)
	fmt.Printf("  %-16s %s\n", "lan_cidr", d.LANCidr)

	if d.Client != "" {
		section("kernel routing decision")
		fmt.Println("  forward (marked, as after tproxy):")
		indent(d.Forward, "    ")
		if d.ForwardVerdict != "" {
			tone := cli.Red
			if strings.HasPrefix(d.ForwardVerdict, "good") {
				tone = cli.Green
			}
			fmt.Printf("    %s\n", tone("^ "+d.ForwardVerdict))
		}
		fmt.Println("  reverse (validation, mark 0):")
		indent(d.Reverse, "    ")
	}

	fmt.Print("  rp_filter:")
	for _, iface := range sortedKeys(d.RPFilter) {
		fmt.Printf(" %s=%s", iface, d.RPFilter[iface])
	}
	fmt.Println()
	if len(d.KernelDrops) > 0 {
		fmt.Print("  kernel drops:")
		for _, k := range sortedKeys(d.KernelDrops) {
			fmt.Printf(" %s=%s", k, d.KernelDrops[k])
		}
		fmt.Println()
	}

	section("forwarding")
	f := d.Forwarding
	fmt.Printf("  ip_forward=%s rp_filter=%s send_redirects=%s\n",
		f.IPForward, f.RPFilter, f.SendRedirects)
	fmt.Printf("  ipv6 forwarding (all)=%s", f.IPv6All)
	for _, iface := range sortedKeys(f.PerInterface) {
		fmt.Printf(" %s:v4=%s", iface, f.PerInterface[iface])
	}
	fmt.Println()
	if f.IPv6All == "0" {
		// Tailscale checks BOTH families: --advertise-exit-node advertises ::/0
		// as well as 0.0.0.0/0, so v6 forwarding off is enough on its own to
		// produce "IP forwarding is disabled" on a box that forwards IPv4
		// perfectly well. The generic wording sends people to check ip_forward,
		// which is not the one that is off.
		fmt.Printf("    %s\n", cli.Yellow(`^ this alone makes Tailscale report "IP forwarding is disabled"`))
		fmt.Printf("    %s\n", cli.Yellow("  even with IPv4 forwarding on. Fix: sudo gw apply"))
	}
	fmt.Printf("  xray listening: %d socket(s)\n", d.XrayListening)

	if d.Client != "" {
		section("client " + d.Client)
		fmt.Printf("  in proxy_clients : %s\n", d.InProxySet)
		fmt.Printf("  in direct_clients: %s\n", d.InDirectSet)
		if d.Conntrack < 0 {
			fmt.Println("  conntrack        : (the conntrack tool is not installed)")
		} else {
			fmt.Printf("  conntrack        : %d entries\n", d.Conntrack)
		}
		fmt.Println("  recent in xray   :")
		if len(d.XrayLines) == 0 {
			fmt.Println("    (none — its packets are not reaching Xray)")
		}
		for _, l := range d.XrayLines {
			fmt.Printf("    %s\n", l)
		}
	}

	fmt.Print(`
Reading this:
  lan-intercepted / listed-intercepted climbing  the client IS being proxied;
                                                 look at Xray, not the firewall
  poisoned-dns climbing                          the destination is private and
                                                 unknown here: either a poisoned
                                                 DNS answer (point the client's
                                                 DNS at this box) or a network
                                                 that IS reachable and is not
                                                 listed — add it to
                                                 routing.extra_local_networks
  killswitch climbing                            traffic reached forward instead
                                                 of being intercepted
  bypass-local climbing                          the destination is being treated
                                                 as local
  all flat                                       the packets never arrive: check
                                                 the client's default gateway
`)
}

func printCounters(counters []diag.Counter) {
	for _, c := range counters {
		value := "-"
		if c.Packets > 0 {
			value = fmt.Sprintf("%d packets", c.Packets)
		}
		fmt.Printf("  %-24s %s\n", c.Name+":", value)
	}
}

func indent(text, prefix string) {
	for _, line := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		fmt.Println(prefix + line)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ----------------------------------------------------------------- trace ----

func cmdTrace(args []string) error {
	cli.NeedRoot("trace")
	if len(args) == 0 {
		return fmt.Errorf("usage: gw trace <client-ip> [seconds]")
	}
	if _, err := netip.ParseAddr(args[0]); err != nil {
		return fmt.Errorf("%q is not a valid IP address", args[0])
	}
	seconds := 20
	if len(args) > 1 {
		n, err := strconv.Atoi(args[1])
		if err != nil || n <= 0 {
			return fmt.Errorf("seconds must be a positive number, not %q", args[1])
		}
		seconds = n
	}

	// Ctrl-C must still reach the rule removal, or the trace rule marks every
	// packet from that client until the next apply.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return diag.Trace{Client: args[0], Seconds: seconds}.Run(ctx, os.Stdout)
}

// --------------------------------------------------------------- history ----

func cmdHistory(args []string) error {
	fs := flag.NewFlagSet("history", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the report as JSON")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}

	hours, client := 48, ""
	for _, arg := range rest {
		if _, err := netip.ParseAddr(arg); err == nil {
			client = arg
			continue
		}
		n, err := strconv.Atoi(arg)
		if err != nil || n <= 0 {
			return fmt.Errorf("usage: gw history [hours] [client-ip]")
		}
		hours = n
	}

	h := diag.Collector{}.CollectHistory(hours, client)
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(h)
	}
	printHistory(h)
	return nil
}

func printHistory(h diag.History) {
	fmt.Printf("%s\n", cli.Green(fmt.Sprintf(
		"== tunnel outages seen by the health probe (last %dh) ==", h.Hours)))
	if len(h.ProbeEvents) > 0 {
		for _, l := range h.ProbeEvents {
			fmt.Printf("  %s\n", l)
		}
	} else {
		cli.Dim("  none. The probe ran and never failed.")
		cli.Dim("  If the client lost the internet inside this window, the tunnel was")
		cli.Dim("  up while that happened: look between the client and this box")
		cli.Dim("  (DNS, wifi, the client gateway setting), not at the tunnel.")
	}

	fmt.Printf("\n%s\n", cli.Green("== service restarts =="))
	cli.Dim("  every xray restart drops every live connection on every client.")
	for _, unit := range sortedKeys(h.Restarts) {
		fmt.Printf("  %-12s %d start(s)\n", unit, h.Restarts[unit])
		for _, l := range h.RestartLines[unit] {
			fmt.Printf("      %s\n", l)
		}
	}

	fmt.Printf("\n%s\n", cli.Green("== kernel complaints =="))
	if len(h.KernelComplaints) == 0 {
		cli.Dim("  none")
	}
	joined := strings.Join(h.KernelComplaints, "\n")
	for _, l := range h.KernelComplaints {
		fmt.Printf("  %s\n", l)
	}
	if strings.Contains(joined, "table full") {
		fmt.Printf("  %s\n", cli.Red("^ conntrack filled: NEW connections were dropped while it was full."))
		fmt.Printf("    %s\n", cli.Red(`That looks exactly like "the internet stopped for a bit".`))
	}
	if lower := strings.ToLower(joined); strings.Contains(lower, "out of memory") ||
		strings.Contains(lower, "oom-kill") {
		fmt.Printf("  %s\n", cli.Red("^ the OOM killer ran. If it took xray, every connection died with it."))
	}

	fmt.Printf("\n%s\n", cli.Green("== pressure right now =="))
	ct := h.Conntrack
	fmt.Printf("  conntrack : %d/%d (%d%%)\n", ct.Current, ct.Max, ct.Percent)
	if ct.Percent >= 60 {
		fmt.Printf("    %s\n", cli.Yellow("^ high. A phone on QUIC opens a lot of UDP flows; raise"))
		fmt.Printf("      %s\n", cli.Yellow("net.netfilter.nf_conntrack_max, or shorten the UDP timeout."))
	}
	loads := make([]string, 0, len(h.LoadAvg))
	for _, l := range h.LoadAvg {
		loads = append(loads, fmt.Sprintf("%.2f", l))
	}
	fmt.Printf("  load      : %s\n", strings.Join(loads, " "))
	fmt.Printf("  xray rss  : %s\n", humanBytes(h.XrayRSS))

	fmt.Printf("\n%s\n", cli.Green("== recorded samples =="))
	if len(h.Samples) == 0 {
		cli.Dim("  none yet (written by the health timer; it starts empty after a")
		cli.Dim("  reboot and fills at one line per probe)")
	} else {
		fmt.Printf("  %d lines\n", len(h.Samples))
		var bad []string
		for _, s := range h.Samples {
			if !strings.Contains(s, " up ") {
				bad = append(bad, s)
			}
		}
		cli.Dim("  non-up samples, newest last:")
		if len(bad) == 0 {
			cli.Dim("  every sample says up")
		}
		for _, s := range tail(bad, 20) {
			fmt.Printf("  %s\n", s)
		}
		cli.Dim("  last 5:")
		for _, s := range tail(h.Samples, 5) {
			fmt.Printf("  %s\n", s)
		}
	}

	title := "== DNS queries per hour"
	if h.Client != "" {
		title += " from " + h.Client
	}
	fmt.Printf("\n%s\n", cli.Green(title+" =="))
	if h.DNSNote != "" {
		cli.Dim("  %s", h.DNSNote)
	}
	widest := 0
	for _, b := range h.DNSPerHour {
		if b.Count > widest {
			widest = b.Count
		}
	}
	for _, b := range h.DNSPerHour {
		bar := ""
		flag := "   <- silence"
		if b.Count > 0 {
			flag = ""
			width := b.Count * 40 / max(widest, 1)
			bar = strings.Repeat("#", max(width, 1))
		}
		fmt.Printf("  %s:00  %6d %s%s\n", strings.Replace(b.Hour, "T", " ", 1), b.Count, bar, flag)
	}

	fmt.Print(`
Reading this:
  outages listed, client dropped at the same time   the tunnel. Look at the
                                                    xray journal at that
                                                    timestamp.
  no outages, but xray restarted                    the restart WAS the outage.
                                                    Every connection dies with
                                                    it; the client notices, the
                                                    probe does not.
  no outages, no restarts                           the box was fine while the
                                                    client was not. Read the DNS
                                                    histogram next.
  DNS silent during the outage                      the client stopped asking
                                                    this box: it left the wifi,
                                                    or it fell back to another
                                                    resolver. Not a gateway
                                                    fault.
  DNS steady through the outage                     the client kept resolving
                                                    but could not move data —
                                                    the data path, not DNS.
  conntrack full / OOM                              cause found; both drop new
                                                    connections while they last.

Run it with the client IP to get that histogram: gw history 48 192.168.1.87
`)
}

func tail(lines []string, n int) []string {
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

// ----------------------------------------------------------------- bench ----

func cmdBench(args []string) error {
	cli.NeedRoot("bench")
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit the result as JSON")
	rest, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	url := ""
	if len(rest) > 0 {
		url = rest[0]
	}

	fmt.Printf("%s\n", cli.Green("== link =="))
	b, err := diag.Collector{}.Bench(url)
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(b)
	}
	printBench(b)
	return nil
}

func printBench(b diag.BenchResult) {
	speed := "?"
	if b.LinkSpeed > 0 {
		speed = strconv.Itoa(b.LinkSpeed)
	}
	fmt.Printf("  %s: %s Mb/s %s\n", b.Interface, speed, b.Duplex)
	if b.LinkSpeed > 0 && b.LinkSpeed <= 100 {
		fmt.Printf("  %s\n", cli.Yellow("! One NIC carries intercepted traffic TWICE — in from the client"))
		fmt.Printf("    %s\n", cli.Yellow(fmt.Sprintf(
			"and out to the internet — so a %d Mb/s link caps clients at about", b.LinkSpeed)))
		fmt.Printf("    %s\n", cli.Yellow(fmt.Sprintf(
			"%d Mb/s. That alone explains a halving.", b.LinkSpeed/2)))
	}
	if b.Duplex == "half" {
		fmt.Printf("  %s\n", cli.Red("! HALF DUPLEX — almost always a bad cable or a forced port speed"))
	}
	fmt.Printf("  errors/drops: rx_drop=%d tx_drop=%d\n", b.RxDrop, b.TxDrop)

	fmt.Printf("\n%s\n", cli.Green("== cpu =="))
	fmt.Printf("  cores: %d   model: %s\n", b.Cores, b.CPUModel)
	if b.AESNI {
		fmt.Println("  aes-ni: yes")
	} else {
		fmt.Println("  aes-ni: NO — TLS is done in software, which is usually the " +
			"ceiling on an old thin client")
	}

	fmt.Printf("\n%s\n", cli.Green("== throughput =="))
	fmt.Printf("  direct (bypassing the tunnel): %.1f Mb/s  (%d bytes)\n", b.DirectMbps, b.DirectBytes)
	fmt.Printf("  through the tunnel           : %.1f Mb/s  (%d bytes)\n", b.TunnelMbps, b.TunnelBytes)
	if b.CPUBusyPct >= 0 {
		fmt.Printf("  cpu busy during the test     : %d%%\n", b.CPUBusyPct)
	}
	if b.DirectMbps > 0 && b.TunnelMbps > 0 {
		fmt.Printf("  tunnel is %.0f%% of direct\n", b.Ratio())
	}
	fmt.Printf("  -> %s\n", b.Verdict())

	fmt.Print(`
If clients are slower than this box, the difference is the LAN leg, not Xray:
intercepted traffic crosses the single NIC twice. A second NIC (a USB 3.0
gigabit adapter) removes that ceiling entirely.
`)
}
