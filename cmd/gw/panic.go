package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/cli"
	"github.com/am1nr/gateway/internal/system"
)

// panicRuleset is a blanket NAT table, and nothing else. It is deliberately the
// smallest possible ruleset: panic mode exists for the moment when the
// generated one is the suspect, so it must not share any of it.
const panicRuleset = `table ip gwpanic
delete table ip gwpanic
table ip gwpanic {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        masquerade
    }
}
`

// resolvBackup is where panic mode keeps the previous resolver config.
const resolvBackup = "/etc/resolv.conf.gw-bak"

// cmdPanic drops to plain NAT so the LAN works while you debug.
//
// This is the opposite of every other command here: it deliberately removes the
// kill switch and lets traffic out unproxied. It exists because a gateway that
// fails closed takes the whole house offline, and at some point the priority
// stops being "stay private" and becomes "let the household use the internet
// while I work out what broke".
func cmdPanic(args []string) error {
	cli.NeedRoot("panic")
	_ = args

	cli.Warn("disabling interception — ALL traffic will go out unproxied via the router")

	// Order matters: the gateway table goes first so nothing is intercepted
	// while the policy routing is being torn down.
	_ = run("nft", "delete", "table", "inet", "gateway")
	_ = run("/usr/local/lib/gateway/ip-rules.sh", "down")
	_ = (system.Systemd{}).Stop("gw-health.timer")

	if err := run("sysctl", "-qw", "net.ipv4.ip_forward=1"); err != nil {
		cli.Warn("could not enable forwarding: %v", err)
	}

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(panicRuleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("could not install the panic ruleset: %v\n%s", err, out)
	}

	restoreResolver()

	cli.Warn("panic mode active. Clients keep working, unproxied. Run 'gw apply' to restore.")
	return nil
}

// restoreResolver points the box at the router when DNS is dead.
//
// Routing alone is not "working internet": resolv.conf still points at AdGuard,
// whose upstreams ride the tunnel that just failed. Without this, panic mode
// looks like it did nothing.
func restoreResolver() {
	if resolves("example.com") {
		cli.Info("DNS still resolving — leaving /etc/resolv.conf alone")
		return
	}

	env := cli.Env("/usr/local/lib/gateway/env")
	router := env["ROUTER"]
	if router == "" {
		cli.Warn("DNS is not resolving and no router is known — set /etc/resolv.conf by hand")
		return
	}

	if current, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		if err := os.WriteFile(resolvBackup, current, 0o644); err != nil {
			cli.Warn("could not back up /etc/resolv.conf: %v", err)
		}
	}
	body := fmt.Sprintf("# Written by `gw panic`. `gw apply` puts this back once "+
		"AdGuard answers.\nnameserver %s\n", router)
	if err := os.WriteFile("/etc/resolv.conf", []byte(body), 0o644); err != nil {
		cli.Warn("could not rewrite /etc/resolv.conf: %v", err)
		return
	}
	cli.Warn("DNS was dead; /etc/resolv.conf now points at the router (%s)", router)
	cli.Warn("previous file kept at %s", resolvBackup)
}

// resolves reports whether a name can be looked up right now.
func resolves(name string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, name)
	return err == nil && len(addrs) > 0
}

// run executes a command, discarding its output.
func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run()
}

// restoreResolverAfterApply undoes a panic-mode DNS fallback, but only once
// AdGuard is actually answering — pointing at a dead resolver is what panic was
// rescuing us from in the first place.
func restoreResolverAfterApply() {
	if _, err := os.Stat(resolvBackup); err != nil {
		return
	}
	// Give AdGuard a moment: it was only just restarted.
	time.Sleep(2 * time.Second)
	if !localResolverAnswers() {
		cli.Warn("AdGuard is not answering yet — leaving the panic DNS fallback in place")
		return
	}
	body := "# Managed by gw — this box resolves through its own AdGuard instance\n" +
		"nameserver 127.0.0.1\noptions edns0\n"
	if err := os.WriteFile("/etc/resolv.conf", []byte(body), 0o644); err != nil {
		cli.Warn("could not restore /etc/resolv.conf: %v", err)
		return
	}
	_ = os.Remove(resolvBackup)
	cli.Info("restored /etc/resolv.conf to the local resolver")
}

// localResolverAnswers asks 127.0.0.1 directly, rather than going through
// whatever resolv.conf currently says.
func localResolverAnswers() bool {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, "127.0.0.1:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	addrs, err := resolver.LookupHost(ctx, "example.com")
	return err == nil && len(addrs) > 0
}
