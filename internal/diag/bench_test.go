package diag

import (
	"strings"
	"testing"
)

// The number this exists to produce. One core pegged on a four-core box is 25%
// of the average, which reads as an idle machine — and "the CPU is the ceiling"
// is the only thing the figure is asked to tell anyone.
func TestPeakBusyPercentFindsOnePeggedCore(t *testing.T) {
	before := map[string]cpuSample{
		"cpu0": {busy: 0, idle: 0},
		"cpu1": {busy: 0, idle: 0},
		"cpu2": {busy: 0, idle: 0},
		"cpu3": {busy: 0, idle: 0},
	}
	after := map[string]cpuSample{
		"cpu0": {busy: 1000, idle: 0},
		"cpu1": {busy: 0, idle: 1000},
		"cpu2": {busy: 0, idle: 1000},
		"cpu3": {busy: 0, idle: 1000},
	}
	if got := peakBusyPercent(before, after); got != 100 {
		t.Fatalf("peakBusyPercent = %d%%, want 100%%: one core was saturated", got)
	}
}

// A genuinely idle box still reads as idle, so the peak does not turn every run
// into a CPU warning.
func TestPeakBusyPercentStaysLowWhenIdle(t *testing.T) {
	before := map[string]cpuSample{"cpu0": {}, "cpu1": {}}
	after := map[string]cpuSample{
		"cpu0": {busy: 10, idle: 990},
		"cpu1": {busy: 5, idle: 995},
	}
	if got := peakBusyPercent(before, after); got != 1 {
		t.Fatalf("peakBusyPercent = %d%%, want 1%%", got)
	}
}

func TestPeakBusyPercentReportsUnsampled(t *testing.T) {
	if got := peakBusyPercent(nil, nil); got != -1 {
		t.Fatalf("peakBusyPercent = %d, want -1 when nothing was sampled", got)
	}
}

// The aggregate "cpu" line is the average this deliberately avoids, so it must
// not become a fifth core that dilutes the peak.
func TestParseCPUSamplesSkipsTheAggregate(t *testing.T) {
	raw := `cpu  100 0 100 1000 0 0 0 0 0 0
cpu0 50 0 50 500 0 0 0 0 0 0
cpu1 50 0 50 500 0 0 0 0 0 0
intr 12345
ctxt 6789
`
	got := parseCPUSamples(raw)
	if len(got) != 2 {
		t.Fatalf("parseCPUSamples returned %d entries (%v), want cpu0 and cpu1 only", len(got), got)
	}
	if _, ok := got["cpu"]; ok {
		t.Error("the aggregate cpu line was kept")
	}
	// user + nice + system + iowait + irq + softirq + steal
	if want := (cpuSample{busy: 100, idle: 500}); got["cpu0"] != want {
		t.Errorf("cpu0 = %+v, want %+v", got["cpu0"], want)
	}
}

// A two-armed box does not hairpin, so the verdict must not send its owner
// shopping for the second card they already have.
func TestVerdictOnTwoCardsDoesNotAskForASecond(t *testing.T) {
	b := BenchResult{
		WAN:        BenchLink{Interface: "enp5s0", Speed: 1000},
		LAN:        &BenchLink{Interface: "enp3s0", Speed: 1000},
		DirectMbps: 900,
		TunnelMbps: 800,
	}
	got := b.Verdict()
	if want := "enp3s0"; !strings.Contains(got, want) {
		t.Fatalf("Verdict = %q, want it to name the LAN card %q", got, want)
	}
	if strings.Contains(got, "A second card") {
		t.Errorf("Verdict = %q, but this box already has two cards", got)
	}
}

// One card still gets the hairpin advice, which is correct there.
func TestVerdictOnOneCardStillRecommendsASecond(t *testing.T) {
	b := BenchResult{
		WAN:        BenchLink{Interface: "eth0", Speed: 1000},
		DirectMbps: 900,
		TunnelMbps: 800,
	}
	if got := b.Verdict(); !strings.Contains(got, "A second card") {
		t.Fatalf("Verdict = %q, want the hairpin advice on a single-armed box", got)
	}
}

// The box that prompted this: a tunnel at 3% of direct. The tunnel is the
// bottleneck and nothing about the LAN enters into it.
func TestVerdictBlamesTheTunnelWhenItIsFarBehind(t *testing.T) {
	b := BenchResult{
		WAN:        BenchLink{Interface: "enp5s0", Speed: 1000},
		LAN:        &BenchLink{Interface: "enp3s0", Speed: 1000},
		DirectMbps: 9.7,
		TunnelMbps: 0.3,
	}
	if got := b.Verdict(); !strings.Contains(got, "TUNNEL is the bottleneck") {
		t.Fatalf("Verdict = %q, want the tunnel blamed at %.0f%% of direct", got, b.Ratio())
	}
}

func TestVerdictReportsAFailedMeasurement(t *testing.T) {
	b := BenchResult{WAN: BenchLink{Interface: "eth0"}, DirectMbps: 900}
	if got := b.Verdict(); !strings.Contains(got, "a measurement failed") {
		t.Fatalf("Verdict = %q, want a failed measurement reported as such", got)
	}
}
