package diag

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// History answers "what happened while I wasn't looking?".
//
// `gw diag` and `gw trace` only see the present. An outage that ended ten
// minutes ago leaves nothing for them to look at, so an intermittent fault
// defeats both: by the time anyone runs them the box looks healthy — and it IS
// healthy, which is why guessing from a clean report goes nowhere.
type History struct {
	Hours  int    `json:"hours"`
	Client string `json:"client,omitempty"`

	// ProbeEvents are the health watchdog's own words.
	ProbeEvents []string `json:"probe_events"`
	// Restarts counts service starts, because every Xray restart drops every
	// live connection on every client — the restart IS the outage, and the
	// probe never sees it.
	Restarts map[string]int `json:"restarts"`
	// RestartLines are the recent journal lines behind those counts.
	RestartLines map[string][]string `json:"restart_lines"`
	// KernelComplaints are the messages that explain an outage nothing else
	// recorded: a full conntrack table, the OOM killer, a flapping link.
	KernelComplaints []string `json:"kernel_complaints"`
	// Samples are the health timer's ring buffer, one line per probe, so an
	// outage that never tripped a threshold still leaves a trace.
	Samples []string `json:"samples"`
	// DNSPerHour is the query count per hour, from AdGuard's log. A gap means
	// the client stopped asking this box — it left the wifi, or fell back to
	// another resolver. Neither is a gateway fault.
	DNSPerHour []DNSBucket `json:"dns_per_hour"`
	DNSNote    string      `json:"dns_note,omitempty"`

	Conntrack ConntrackPressure `json:"conntrack"`
	LoadAvg   []float64         `json:"load"`
	XrayRSS   int64             `json:"xray_rss_bytes"`
}

// DNSBucket is one hour of query volume.
type DNSBucket struct {
	Hour  string `json:"hour"`
	Count int    `json:"count"`
}

// ConntrackPressure is how close the connection table is to full. A phone on
// QUIC opens a lot of UDP flows, and while the table is full NEW connections
// are dropped — which looks exactly like "the internet stopped for a bit".
type ConntrackPressure struct {
	Current int64 `json:"current"`
	Max     int64 `json:"max"`
	Percent int   `json:"percent"`
}

var (
	probeEventRE = regexp.MustCompile(
		`probe failed|INTERCEPTION|healthy again|lifeline|restarting xray|conntrack`)
	restartEventRE = regexp.MustCompile(
		`Started|Stopped|Main process exited|Scheduled restart|Failed with result`)
	kernelComplaintRE = regexp.MustCompile(`(?i)` + strings.Join([]string{
		"conntrack table full", "nf_conntrack: table full", "out of memory",
		"oom-kill", "martian", "link is down", "link is not ready",
		"carrier lost", "tx unit hang", "reset adapter",
	}, "|"))
)

// historyUnits are the services whose restarts can explain an outage.
var historyUnits = []string{"xray", "AdGuardHome", "tailscaled", "gw-web"}

// unitNames appends the .service suffix systemd expects.
func unitNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, n+".service")
	}
	return out
}

// AdGuardQueryLog is where AdGuard records one line per query.
const AdGuardQueryLog = "/opt/AdGuardHome/data/querylog.json"

// CollectHistory reads back what was recorded while the fault was happening.
func (c Collector) CollectHistory(hours int, client string) History {
	if hours <= 0 {
		hours = 48
	}
	since := fmt.Sprintf("-%dh", hours)

	h := History{
		Hours:        hours,
		Client:       client,
		Restarts:     map[string]int{},
		RestartLines: map[string][]string{},
	}

	h.ProbeEvents = journalMatching(since, probeEventRE, []string{"-t", "gw-health"}, 200)

	// LoadState, not is-active: systemctl reports a unit it has never heard of
	// as "inactive", so is-active cannot tell an absent unit from a stopped
	// one — and listing tailscaled on a box without Tailscale is noise that
	// makes the real restarts harder to see.
	known := c.Systemd.Querying().ShowMany(unitNames(historyUnits), "LoadState")
	for _, unit := range historyUnits {
		if props, ok := known[unit+".service"]; !ok || props["LoadState"] == "not-found" {
			continue
		}
		lines := journalMatching(since, restartEventRE, []string{"-u", unit}, 200)
		starts := 0
		for _, l := range lines {
			if strings.Contains(l, "Started") {
				starts++
			}
		}
		h.Restarts[unit] = starts
		h.RestartLines[unit] = lastN(lines, 12)
	}

	h.KernelComplaints = lastN(journalMatching(since, kernelComplaintRE, []string{"-k"}, 400), 25)
	h.Samples = readSamples()
	h.Conntrack = conntrackPressure()
	h.LoadAvg = loadAverage()
	h.XrayRSS = processRSS("xray")
	h.DNSPerHour, h.DNSNote = dnsPerHour(hours, client)
	return h
}

// journalMatching reads the journal and keeps the lines that match.
//
// Filtering here rather than with `grep` in a pipeline means the pattern is one
// regexp in one place, and the caller gets structured lines rather than text.
func journalMatching(since string, pattern *regexp.Regexp, selector []string, limit int) []string {
	args := append([]string{"--since", since, "--no-pager", "-o", "short-iso"}, selector...)
	out, err := run(20*time.Second, "journalctl", args...)
	if err != nil {
		return nil
	}
	var kept []string
	for _, line := range strings.Split(out, "\n") {
		if line != "" && pattern.MatchString(line) {
			kept = append(kept, line)
			if len(kept) >= limit {
				break
			}
		}
	}
	return kept
}

func lastN(lines []string, n int) []string {
	if len(lines) <= n {
		return lines
	}
	return lines[len(lines)-n:]
}

// readSamples reads the health timer's ring buffer from tmpfs.
func readSamples() []string {
	raw, err := os.ReadFile(StateDir + "/history")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func conntrackPressure() ConntrackPressure {
	p := ConntrackPressure{
		Current: readInt("/proc/sys/net/netfilter/nf_conntrack_count"),
		Max:     readInt("/proc/sys/net/netfilter/nf_conntrack_max"),
	}
	if p.Current < 0 {
		p.Current = 0
	}
	if p.Max > 0 {
		p.Percent = int(p.Current * 100 / p.Max)
	}
	return p
}

func loadAverage() []float64 {
	fields := strings.Fields(readTrimmed("/proc/loadavg"))
	var out []float64
	for i := 0; i < 3 && i < len(fields); i++ {
		v, _ := strconv.ParseFloat(fields[i], 64)
		out = append(out, v)
	}
	return out
}

// processRSS totals the resident memory of every process with this name.
func processRSS(name string) int64 {
	out, err := run(5*time.Second, "ps", "-o", "rss=", "-C", name)
	if err != nil {
		return 0
	}
	var total int64
	for _, line := range strings.Fields(out) {
		if kb, err := strconv.ParseInt(line, 10, 64); err == nil {
			total += kb * 1024
		}
	}
	return total
}

// dnsPerHour buckets AdGuard's query log by hour.
//
// This is the other half of the split. If the box was healthy the whole time,
// the next question is whether the client was still talking to it at all — and
// AdGuard already wrote that down, one line per query, with the client's
// address.
func dnsPerHour(hours int, client string) ([]DNSBucket, string) {
	path := os.Getenv("GW_AGH_LOG")
	if path == "" {
		path = AdGuardQueryLog
	}

	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour)
	buckets := map[string]int{}
	found := false

	// AdGuard rotates to querylog.json.1, so both are read.
	for _, p := range []string{path, path + ".1"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		found = true
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var rec struct {
				IP string `json:"IP"`
				T  string `json:"T"`
			}
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			if client != "" && rec.IP != client {
				continue
			}
			if len(rec.T) < 13 {
				continue
			}
			stamp, err := time.Parse(time.RFC3339, rec.T)
			if err != nil {
				// AdGuard's timestamps carry sub-second precision and a zone;
				// anything else is not a record we can place in time.
				continue
			}
			if stamp.Before(cutoff) {
				continue
			}
			buckets[stamp.Format("2006-01-02T15")]++
		}
	}

	if !found {
		return nil, path + " is not readable — run this as root, or AdGuard query logging is off"
	}
	if len(buckets) == 0 {
		note := "no queries in this window"
		if client != "" {
			note += " from " + client
		}
		return nil, note + ". If the client was online and using this box for DNS, " +
			"there would be some — check what resolver it is actually using."
	}

	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Every hour between the first and last is emitted, including the empty
	// ones: a gap is the whole point of the histogram.
	start, _ := time.ParseInLocation("2006-01-02T15", keys[0], time.Local)
	end, _ := time.ParseInLocation("2006-01-02T15", keys[len(keys)-1], time.Local)
	var out []DNSBucket
	for t := start; !t.After(end); t = t.Add(time.Hour) {
		key := t.Format("2006-01-02T15")
		out = append(out, DNSBucket{Hour: key, Count: buckets[key]})
	}
	return out, ""
}
