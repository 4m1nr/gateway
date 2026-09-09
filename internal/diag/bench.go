package diag

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/system"
)

// BenchLink is one card's physical link state.
//
// Both cards are measured on a two-armed box. The uplink caps what this box can
// fetch, which is what the throughput numbers below exercise; the LAN card caps
// what a client can pull through it, and nothing else in the report would show
// a card that quietly negotiated 100 Mb/s half duplex. Reporting only the
// uplink made the commonest cause of "the gateway is slow for everyone" the one
// thing the benchmark could not see.
type BenchLink struct {
	Interface string `json:"interface"`
	Speed     int    `json:"link_speed_mbits"` // -1 when unknown
	Duplex    string `json:"duplex"`
	RxDrop    int64  `json:"rx_drop"`
	TxDrop    int64  `json:"tx_drop"`
}

// BenchResult is what a throughput measurement found.
type BenchResult struct {
	WAN BenchLink `json:"wan"`
	// LAN is the second card on a two-armed box, and nil otherwise. Its absence
	// is what says the box hairpins: with one card every intercepted packet
	// crosses it twice, and the usable ceiling is half what it negotiated.
	LAN         *BenchLink `json:"lan,omitempty"`
	Cores       int        `json:"cores"`
	CPUModel    string     `json:"cpu_model"`
	AESNI       bool       `json:"aes_ni"`
	DirectMbps  float64    `json:"direct_mbits"`
	TunnelMbps  float64    `json:"tunnel_mbits"`
	DirectBytes int64      `json:"direct_bytes"`
	TunnelBytes int64      `json:"tunnel_bytes"`
	// CPUPeakPct is the busiest single core during the test, not the average
	// across all of them. Xray's crypto for one connection is bound to one
	// core, so on this four-core box a fully pegged core averages out to 25%
	// and a mostly idle box to 0% — the aggregate cannot distinguish "the CPU
	// is the ceiling" from "the CPU is asleep", which is the only question the
	// number is here to answer. -1 when it could not be sampled.
	CPUPeakPct int `json:"cpu_peak_core_pct"`
}

// Ratio is the tunnel's throughput as a percentage of direct.
func (b BenchResult) Ratio() float64 {
	if b.DirectMbps <= 0 {
		return 0
	}
	return b.TunnelMbps / b.DirectMbps * 100
}

// Verdict names the bottleneck.
//
// Halved throughput through a gateway usually has a boring cause. There are
// three, and guessing between them is how an afternoon disappears.
func (b BenchResult) Verdict() string {
	if b.DirectMbps <= 0 || b.TunnelMbps <= 0 {
		return "a measurement failed — check connectivity, and see the byte counts above"
	}
	switch {
	case b.Ratio() < 60:
		return "the TUNNEL is the bottleneck: CPU (see aes-ni above), the server, " +
			"or the path to it. Not the LAN."
	case b.WAN.Speed > 0 && b.DirectMbps < float64(b.WAN.Speed)/2*0.8:
		return "direct is already well under half the link speed, so the bottleneck " +
			"is upstream of this box, not the gateway."
	case b.LAN != nil:
		return "the tunnel keeps up here, and traffic does not hairpin — it comes " +
			"in " + b.LAN.Interface + " and leaves " + b.WAN.Interface + ". A slower " +
			"client is the LAN path itself: cabling, the switch, or the client."
	default:
		return "the tunnel keeps up here, so a slower client is the LAN path: " +
			"one NIC carries intercepted traffic twice. A second card removes " +
			"that ceiling — see 'Two network cards' in the README."
	}
}

// DefaultBenchURL is 50 MB from a host that is fast nearly everywhere.
const DefaultBenchURL = "https://speed.cloudflare.com/__down?bytes=50000000"

// Bench measures the three things that actually limit a gateway: the link, the
// CPU, and the tunnel.
func (c Collector) Bench(url string) (BenchResult, error) {
	if url == "" {
		url = DefaultBenchURL
	}
	env := readEnv(c.envPath())
	res := BenchResult{Cores: numCPU()}
	if env["WAN_IF"] == "" {
		return res, fmt.Errorf("no WAN interface is known — has `gw apply` run?")
	}
	res.WAN = linkState(env["WAN_IF"])
	if lan := env["LAN_IF"]; lan != "" {
		l := linkState(lan)
		res.LAN = &l
	}
	res.CPUModel, res.AESNI = cpuInfo()

	before := cpuSamples()

	socks := env["SOCKS_PORT"]
	if socks == "" {
		socks = "10808"
	}

	// Running as the xray user bypasses the tunnel: the output chain returns
	// early on that uid. That is what makes "direct" mean direct.
	direct, directBytes := curlSpeed(true, "", url)
	tunnel, tunnelBytes := curlSpeed(false, socks, url)

	after := cpuSamples()
	res.CPUPeakPct = peakBusyPercent(before, after)

	// bytes/s -> Mb/s
	res.DirectMbps = direct * 8 / 1_000_000
	res.TunnelMbps = tunnel * 8 / 1_000_000
	res.DirectBytes, res.TunnelBytes = directBytes, tunnelBytes
	return res, nil
}

// curlSpeed measures one download. curl reports its own throughput, which is
// more honest than timing the wrapper: it excludes DNS and connection setup and
// counts the bytes that actually arrived.
func curlSpeed(asXray bool, socksPort, url string) (bytesPerSec float64, size int64) {
	args := []string{
		"-o", "/dev/null", "-s", "--max-time", "120",
		"-w", "%{speed_download} %{size_download}",
	}
	if socksPort != "" {
		args = append(args, "--socks5-hostname", "127.0.0.1:"+socksPort)
	}
	args = append(args, url)

	var out string
	if asXray {
		out, _ = system.RunAsUser("xray", 130*time.Second, "curl", args...)
	} else {
		out, _ = run(130*time.Second, "curl", args...)
	}

	// curl writes its -w output even when the transfer fails, so the fields are
	// parsed and validated rather than trusted to be present.
	fields := strings.Fields(strings.TrimSpace(out))
	if len(fields) >= 1 {
		bytesPerSec, _ = strconv.ParseFloat(fields[0], 64)
	}
	if len(fields) >= 2 {
		size, _ = strconv.ParseInt(fields[1], 10, 64)
	}
	return bytesPerSec, size
}

func numCPU() int {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	return strings.Count(string(raw), "processor\t:")
}

func cpuInfo() (model string, aesni bool) {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "model name":
			if model == "" {
				model = strings.TrimSpace(value)
			}
		case "flags":
			// Padded so "aes" does not match "aes_something" or "pclmulqdq".
			if strings.Contains(" "+strings.TrimSpace(value)+" ", " aes ") {
				aesni = true
			}
		}
	}
	return model, aesni
}

func interfaceDrops(iface string) (rx, tx int64) {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		name, rest, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) != iface {
			continue
		}
		f := strings.Fields(rest)
		// receive: bytes packets errs drop ...  transmit: bytes packets errs drop ...
		if len(f) >= 12 {
			rx, _ = strconv.ParseInt(f[3], 10, 64)
			tx, _ = strconv.ParseInt(f[11], 10, 64)
		}
		return rx, tx
	}
	return 0, 0
}

type cpuSample struct{ busy, idle int64 }

// cpuSamples reads /proc/stat's per-core lines, keyed by core name.
//
// Per-core rather than the aggregate "cpu" line, because the aggregate answers
// the wrong question. One connection's crypto runs on one core, so a core at
// 100% shows up as 100/cores in the average — 25% on a four-core box, which
// reads as a machine with plenty left. The busiest core is what says whether
// the CPU is the ceiling.
func cpuSamples() map[string]cpuSample {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	return parseCPUSamples(string(raw))
}

func parseCPUSamples(raw string) map[string]cpuSample {
	samples := make(map[string]cpuSample)
	for _, line := range strings.Split(raw, "\n") {
		f := strings.Fields(line)
		// "cpu0", "cpu1", ... — the bare "cpu" total is skipped, being the
		// average this exists to avoid.
		if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") || f[0] == "cpu" {
			continue
		}
		n := func(i int) int64 { v, _ := strconv.ParseInt(f[i], 10, 64); return v }
		// user nice system idle iowait irq softirq steal
		samples[f[0]] = cpuSample{
			busy: n(1) + n(2) + n(3) + n(5) + n(6) + n(7) + n(8),
			idle: n(4),
		}
	}
	return samples
}

// peakBusyPercent returns the busiest core's utilisation across the interval,
// or -1 when nothing could be sampled.
func peakBusyPercent(before, after map[string]cpuSample) int {
	peak := -1
	for name, a := range after {
		b, ok := before[name]
		if !ok {
			continue
		}
		busy := a.busy - b.busy
		total := busy + (a.idle - b.idle)
		if total <= 0 {
			continue
		}
		if pct := int(busy * 100 / total); pct > peak {
			peak = pct
		}
	}
	return peak
}

// linkState reads what a card negotiated, and what it has dropped.
func linkState(iface string) BenchLink {
	l := BenchLink{Interface: iface, Speed: -1, Duplex: "?"}
	if v := readInt(fmt.Sprintf("/sys/class/net/%s/speed", iface)); v > 0 {
		l.Speed = int(v)
	}
	if d := readTrimmed(fmt.Sprintf("/sys/class/net/%s/duplex", iface)); d != "" {
		l.Duplex = d
	}
	l.RxDrop, l.TxDrop = interfaceDrops(iface)
	return l
}

func readTrimmed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func readInt(path string) int64 {
	v, err := strconv.ParseInt(readTrimmed(path), 10, 64)
	if err != nil {
		return -1
	}
	return v
}
