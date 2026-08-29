package diag

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/system"
)

// BenchResult is what a throughput measurement found.
type BenchResult struct {
	Interface   string  `json:"interface"`
	LinkSpeed   int     `json:"link_speed_mbits"` // -1 when unknown
	Duplex      string  `json:"duplex"`
	RxDrop      int64   `json:"rx_drop"`
	TxDrop      int64   `json:"tx_drop"`
	Cores       int     `json:"cores"`
	CPUModel    string  `json:"cpu_model"`
	AESNI       bool    `json:"aes_ni"`
	DirectMbps  float64 `json:"direct_mbits"`
	TunnelMbps  float64 `json:"tunnel_mbits"`
	DirectBytes int64   `json:"direct_bytes"`
	TunnelBytes int64   `json:"tunnel_bytes"`
	CPUBusyPct  int     `json:"cpu_busy_pct"`
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
	case b.LinkSpeed > 0 && b.DirectMbps < float64(b.LinkSpeed)/2*0.8:
		return "direct is already well under half the link speed, so the bottleneck " +
			"is upstream of this box, not the gateway."
	default:
		return "the tunnel keeps up here, so a slower client is the LAN path: " +
			"one NIC carries intercepted traffic twice."
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
	res := BenchResult{
		Interface: env["WAN_IF"],
		LinkSpeed: -1,
		Duplex:    "?",
		Cores:     numCPU(),
	}
	if res.Interface == "" {
		return res, fmt.Errorf("no WAN interface is known — has `gw apply` run?")
	}

	if v := readInt(fmt.Sprintf("/sys/class/net/%s/speed", res.Interface)); v > 0 {
		res.LinkSpeed = int(v)
	}
	if d := readTrimmed(fmt.Sprintf("/sys/class/net/%s/duplex", res.Interface)); d != "" {
		res.Duplex = d
	}
	res.RxDrop, res.TxDrop = interfaceDrops(res.Interface)
	res.CPUModel, res.AESNI = cpuInfo()

	before := cpuBusy()

	socks := env["SOCKS_PORT"]
	if socks == "" {
		socks = "10808"
	}

	// Running as the xray user bypasses the tunnel: the output chain returns
	// early on that uid. That is what makes "direct" mean direct.
	direct, directBytes := curlSpeed(true, "", url)
	tunnel, tunnelBytes := curlSpeed(false, socks, url)

	after := cpuBusy()
	res.CPUBusyPct = busyPercent(before, after)

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

func cpuBusy() cpuSample {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 9 {
			return cpuSample{}
		}
		n := func(i int) int64 { v, _ := strconv.ParseInt(f[i], 10, 64); return v }
		// user nice system idle iowait irq softirq steal
		busy := n(1) + n(2) + n(3) + n(5) + n(6) + n(7) + n(8)
		return cpuSample{busy: busy, idle: n(4)}
	}
	return cpuSample{}
}

func busyPercent(before, after cpuSample) int {
	busy := after.busy - before.busy
	idle := after.idle - before.idle
	total := busy + idle
	if total <= 0 {
		return -1
	}
	return int(busy * 100 / total)
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
