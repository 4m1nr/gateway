// Package diag answers "what is this box actually doing?" — for the CLI and
// for the dashboard, from one implementation.
//
// Everything here reads. Nothing in this package changes the system.
package diag

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/am1nr/gateway/internal/system"
)

// StateDir is where the health watchdog records what it last saw.
const StateDir = "/run/gateway"

// TunnelState is the watchdog's verdict.
type TunnelState string

const (
	// Up means intercepted traffic reaches the tunnel.
	Up TunnelState = "up"
	// Degraded means Xray is fine but the packets are not getting to it.
	// Reporting this as "down" sends you to the wrong half of the system.
	Degraded TunnelState = "degraded"
	// Down means consecutive probes failed.
	Down TunnelState = "down"
	// Unknown means the health check has not run yet.
	Unknown TunnelState = "unknown"
)

// Unit is one systemd unit's state.
type Unit struct {
	Name    string `json:"name"`
	Active  string `json:"active"`
	Enabled string `json:"enabled"`
}

// Firewall is what the live ruleset says.
type Firewall struct {
	Loaded          bool     `json:"loaded"`
	KillswitchDrops int      `json:"killswitch_drops"`
	ProxyClients    []string `json:"proxy_clients"`
	DirectClients   []string `json:"direct_clients"`
	BlockedClients  []string `json:"blocked_clients"`
}

// Traffic is one outbound's byte counters, from Xray's stats API.
type Traffic struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

// SystemInfo is the box itself.
type SystemInfo struct {
	Uptime        int64     `json:"uptime"`
	Load          []float64 `json:"load"`
	MemTotal      int64     `json:"mem_total"`
	MemAvailable  int64     `json:"mem_available"`
	DiskTotal     int64     `json:"disk_total"`
	DiskFree      int64     `json:"disk_free"`
	Time          int64     `json:"time"`
	XrayUptimeSec int64     `json:"xray_uptime_sec"`
}

// Status is everything the dashboard's overview and `gw status` report.
type Status struct {
	Tunnel        TunnelState        `json:"tunnel"`
	Detail        string             `json:"detail"`
	Fails         int                `json:"fails"`
	Lifeline      bool               `json:"lifeline"`
	DefaultPolicy string             `json:"default_policy"`
	LAN           string             `json:"lan"`
	BoxIP         string             `json:"box_ip"`
	Profiles      []string           `json:"profiles"`
	Units         []Unit             `json:"units"`
	Firewall      Firewall           `json:"firewall"`
	Traffic       map[string]Traffic `json:"traffic"`
	System        SystemInfo         `json:"system"`
}

// Collector gathers status. The fields exist so tests can point it at a
// throwaway tree instead of the live system.
type Collector struct {
	// Root prefixes the files that are read. "/" in production.
	Root string
	// Systemd talks to init. Zero value is fine.
	Systemd system.Systemd
	// EnvPath is the rendered env file. Defaults to the installed location.
	EnvPath string
}

func (c Collector) root() string {
	if c.Root == "" {
		return "/"
	}
	return c.Root
}

func (c Collector) envPath() string {
	if c.EnvPath != "" {
		return c.EnvPath
	}
	return filepath.Join(c.root(), "usr/local/lib/gateway/env")
}

func (c Collector) stateFile(name string) string {
	return filepath.Join(c.root(), strings.TrimPrefix(StateDir, "/"), name)
}

// read returns a trimmed state file, or the fallback.
func (c Collector) read(name, fallback string) string {
	raw, err := os.ReadFile(c.stateFile(name))
	if err != nil {
		return fallback
	}
	return strings.TrimSpace(string(raw))
}

// Collect gathers everything. Individual sources failing degrade that section
// rather than the whole report: a box with a broken Xray still needs `gw
// status` to say so.
func (c Collector) Collect() Status {
	env := readEnv(c.envPath())

	s := Status{
		Profiles:      []string{},
		Tunnel:        TunnelState(c.read("tunnel", string(Unknown))),
		Detail:        c.read("detail", ""),
		Lifeline:      c.read("lifeline", "0") == "1",
		DefaultPolicy: env["DEFAULT_POLICY"],
		LAN:           env["LAN_CIDR"],
		BoxIP:         env["BOX_IP"],
		Traffic:       map[string]Traffic{},
	}
	s.Fails, _ = strconv.Atoi(c.read("fails", "0"))
	if p := env["PROFILES"]; p != "" {
		s.Profiles = strings.Split(p, ",")
	}
	if s.DefaultPolicy == "" {
		s.DefaultPolicy = "proxy"
	}

	// The four sources are independent and each shells out, so they run
	// concurrently: the dashboard polls this, and serially the report takes as
	// long as the slowest tool plus everything else.
	var wg sync.WaitGroup
	var units []Unit
	var fw Firewall
	var traffic map[string]Traffic
	var sysinfo SystemInfo

	wg.Add(4)
	go func() { defer wg.Done(); units = c.units() }()
	go func() { defer wg.Done(); fw = c.firewall() }()
	go func() { defer wg.Done(); traffic = c.traffic(env["API_PORT"]) }()
	go func() { defer wg.Done(); sysinfo = c.systemInfo() }()
	wg.Wait()

	if units == nil {
		units = []Unit{}
	}
	s.Units, s.Firewall, s.Traffic, s.System = units, fw, traffic, sysinfo
	return s
}

// stackUnits are reported by status, in the order they matter at boot.
var stackUnits = []string{
	"gateway.target", "gw-network.service", "xray.service",
	"AdGuardHome.service", "tailscaled.service", "gw-web.service",
	"gw-health.timer", "gw-geoupdate.timer", "gw-update.timer",
}

func (c Collector) units() []Unit {
	all := c.Systemd.Querying().ShowMany(stackUnits, "ActiveState", "UnitFileState", "LoadState")
	var out []Unit
	// Ranged over stackUnits, not the map, so the report keeps boot order
	// rather than Go's map iteration order.
	for _, name := range stackUnits {
		props, ok := all[name]
		if !ok || props["LoadState"] == "not-found" {
			continue
		}
		out = append(out, Unit{
			Name:    name,
			Active:  orUnknown(props["ActiveState"]),
			Enabled: orUnknown(props["UnitFileState"]),
		})
	}
	return out
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

var (
	packetsRE = regexp.MustCompile(`packets (\d+)`)
	statRE    = regexp.MustCompile(`outbound>>>([^>]+)>>>traffic>>>(uplink|downlink)`)
)

func (c Collector) firewall() Firewall {
	// Non-nil slices throughout: these are consumed as JSON by the dashboard,
	// and null where [] is meant forces a null check at every use site.
	fw := Firewall{
		ProxyClients:   []string{},
		DirectClients:  []string{},
		BlockedClients: []string{},
	}
	out, err := run(5*time.Second, "nft", "list", "table", "inet", "gateway")
	if err != nil {
		return fw
	}
	fw.Loaded = true

	// There are two killswitch rules — listed clients and the LAN catch-all —
	// so they are summed. Reporting only one would understate what the gateway
	// actually refused.
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "killswitch") {
			continue
		}
		if m := packetsRE.FindStringSubmatch(line); m != nil {
			n, _ := strconv.Atoi(m[1])
			fw.KillswitchDrops += n
		}
	}
	fw.ProxyClients = setElements(out, "proxy_clients")
	fw.DirectClients = setElements(out, "direct_clients")
	fw.BlockedClients = setElements(out, "blocked_clients")
	return fw
}

// setElements pulls a named set's members out of `nft list table` output.
//
// nft wraps a long element list across several lines and indents the
// continuation with tabs, so a single-line pattern silently reports an empty
// set — which reads as "no clients are intercepted" on a box where they are.
func setElements(out, name string) []string {
	re := regexp.MustCompile(`(?s)set ` + name + ` \{.*?elements = \{(.*?)\}`)
	m := re.FindStringSubmatch(out)
	if m == nil {
		return []string{}
	}
	var elems []string
	for _, part := range strings.Split(m[1], ",") {
		if v := strings.TrimSpace(part); v != "" {
			elems = append(elems, v)
		}
	}
	if elems == nil {
		return []string{}
	}
	return elems
}

func (c Collector) traffic(apiPort string) map[string]Traffic {
	out := map[string]Traffic{}
	if apiPort == "" {
		apiPort = "10085"
	}
	// Asking a dead gRPC server costs the full timeout, and the dashboard polls
	// this. If Xray is not running there are no counters to fetch anyway.
	if c.Systemd.Querying().IsActive("xray.service") != "active" {
		return out
	}
	raw, err := run(3*time.Second, "xray", "api", "statsquery", "--server=127.0.0.1:"+apiPort)
	if err != nil {
		return out
	}
	var doc struct {
		Stat []struct {
			Name  string `json:"name"`
			Value any    `json:"value"`
		} `json:"stat"`
	}
	if json.Unmarshal([]byte(raw), &doc) != nil {
		return out
	}
	for _, s := range doc.Stat {
		m := statRE.FindStringSubmatch(s.Name)
		if m == nil {
			continue
		}
		// Xray reports the value as a string or a number depending on version.
		var v int64
		switch t := s.Value.(type) {
		case string:
			v, _ = strconv.ParseInt(t, 10, 64)
		case float64:
			v = int64(t)
		}
		entry := out[m[1]]
		if m[2] == "uplink" {
			entry.Uplink = v
		} else {
			entry.Downlink = v
		}
		out[m[1]] = entry
	}
	return out
}

func (c Collector) systemInfo() SystemInfo {
	info := SystemInfo{Time: time.Now().Unix()}

	if raw, err := os.ReadFile(filepath.Join(c.root(), "proc/uptime")); err == nil {
		if first, _, _ := strings.Cut(string(raw), " "); first != "" {
			f, _ := strconv.ParseFloat(first, 64)
			info.Uptime = int64(f)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(c.root(), "proc/loadavg")); err == nil {
		fields := strings.Fields(string(raw))
		for i := 0; i < 3 && i < len(fields); i++ {
			f, _ := strconv.ParseFloat(fields[i], 64)
			info.Load = append(info.Load, f)
		}
	}
	if raw, err := os.ReadFile(filepath.Join(c.root(), "proc/meminfo")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			key, rest, ok := strings.Cut(line, ":")
			if !ok {
				continue
			}
			fields := strings.Fields(rest)
			if len(fields) == 0 {
				continue
			}
			kb, _ := strconv.ParseInt(fields[0], 10, 64)
			switch key {
			case "MemTotal":
				info.MemTotal = kb * 1024
			case "MemAvailable":
				info.MemAvailable = kb * 1024
			}
		}
	}
	var st syscall.Statfs_t
	if syscall.Statfs(c.root(), &st) == nil {
		info.DiskTotal = int64(st.Blocks) * st.Bsize
		info.DiskFree = int64(st.Bavail) * st.Bsize
	}

	// How long Xray has been up, because a restart is invisible after the fact
	// and is itself an outage: it drops every live connection on every client.
	// Only while it is actually running — ActiveEnterTimestamp survives a stop,
	// so an inactive unit would otherwise report a cheerful uptime.
	if sd := c.Systemd.Querying(); sd.IsActive("xray.service") == "active" {
		props := sd.Show("xray.service", "ActiveEnterTimestamp")
		if ts := props["ActiveEnterTimestamp"]; ts != "" {
			if started, err := time.Parse("Mon 2006-01-02 15:04:05 MST", ts); err == nil {
				info.XrayUptimeSec = int64(time.Since(started).Seconds())
			}
		}
	}
	return info
}

// run executes a read-only command under a deadline.
//
// The deadline is not optional. `xray api statsquery` talks to a loopback gRPC
// server and blocks for three seconds when nothing is listening — which is
// exactly the case on a box whose Xray is down, and exactly when the dashboard
// is being refreshed most. Status must stay fast when things are broken.
func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// runCombined is run, but the output is returned even when the command failed.
//
// For the routing probes that failing IS the result: `ip route get` refusing a
// martian source is the answer being looked for, not an error to discard.
func runCombined(timeout time.Duration, name string, args ...string) (string, error) {
	out, err := run(timeout, name, args...)
	return out, err
}

// readEnv parses the rendered env file, stripping one layer of shell quoting.
func readEnv(path string) map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = strings.Trim(v, `"`)
		}
	}
	return out
}
