package diag

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Trace follows one client's packets rule by rule, live.
//
// Counters say which rules fired; they cannot say which rules ONE client's
// packets went through, or where they stopped. nftrace does exactly that.
type Trace struct {
	// Client is the source address being traced.
	Client string
	// Seconds is how long to watch.
	Seconds int
}

var traceHandleRE = regexp.MustCompile(`# handle (\d+)`)

// Run installs a trace rule, streams the matching packets to out, and removes
// the rule again.
//
// The rule is inserted at the TOP of prerouting: tracing has to be switched on
// before any rule can decide the packet's fate. Removal is unconditional — a
// trace rule left behind marks every packet from that client forever, which is
// a slow leak of CPU and journal space that nothing would ever attribute to
// this command.
func (t Trace) Run(ctx context.Context, out io.Writer) error {
	if t.Client == "" {
		return fmt.Errorf("usage: gw trace <client-ip> [seconds]")
	}
	if _, err := run(5*time.Second, "nft", "list", "table", "inet", "gateway"); err != nil {
		return fmt.Errorf("the gateway table is not loaded — run 'sudo gw apply'")
	}

	if _, err := run(10*time.Second, "nft", "insert", "rule", "inet", "gateway",
		"prerouting", "ip", "saddr", t.Client, "meta", "nftrace", "set", "1"); err != nil {
		return fmt.Errorf("could not install the trace rule: %w", err)
	}
	defer t.removeRule(out)

	seconds := t.Seconds
	if seconds <= 0 {
		seconds = 20
	}

	fmt.Fprintf(out, "tracing %s for %ds — generate traffic on that device now\n", t.Client, seconds)
	fmt.Fprintf(out, "(each line is one rule the packet reached; the last line before "+
		"a gap is where it stopped)\n\n")

	// The context bounds the whole run; the timer bounds this trace. Whichever
	// fires first stops the monitor, and the deferred removal still runs.
	traceCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(traceCtx, "nft", "monitor", "trace")
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start `nft monitor trace`: %w", err)
	}

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		fmt.Fprintln(out, scanner.Text())
	}
	// A timeout is the normal way this ends, not a failure.
	_ = cmd.Wait()
	return nil
}

// removeRule deletes the trace rule by handle.
//
// By handle rather than by re-matching text: nft prints rules in a form that
// does not always round-trip, and deleting the wrong rule from prerouting would
// be considerably worse than leaving this one behind.
func (t Trace) removeRule(out io.Writer) {
	listing, err := run(10*time.Second, "nft", "-a", "list", "chain", "inet", "gateway", "prerouting")
	if err != nil {
		fmt.Fprintf(out, "could not list the chain to remove the trace rule: %v\n", err)
		return
	}
	for _, line := range strings.Split(listing, "\n") {
		if !strings.Contains(line, "nftrace set 1") || !strings.Contains(line, t.Client) {
			continue
		}
		m := traceHandleRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if _, err := run(10*time.Second, "nft", "delete", "rule", "inet", "gateway",
			"prerouting", "handle", m[1]); err != nil {
			fmt.Fprintf(out, "could not remove the trace rule (handle %s): %v\n", m[1], err)
			fmt.Fprintf(out, "remove it by hand: nft delete rule inet gateway prerouting handle %s\n", m[1])
			return
		}
		fmt.Fprintln(out, "trace rule removed")
		return
	}
	fmt.Fprintln(out, "trace rule removed")
}
