package action

import (
	"strings"
	"testing"
)

// The whitelist is the authorisation surface. Anything not in it must be
// refused by name, before any process is started.
func TestOnlyWhitelistedCommandsRun(t *testing.T) {
	h := newHandler(t)
	for _, name := range []string{
		"", "panic", "disable", "trace", "init", "web-passwd",
		"rm", "sh", "status; rm -rf /", "../../bin/sh", "STATUS",
	} {
		resp := h.Handle(Request{Action: "run_command", Command: name})
		if resp.OK {
			t.Errorf("command %q was accepted", name)
		}
	}
}

// The commands left out are left out for reasons. If one is ever added back,
// this fails and the reasoning has to be revisited rather than lost.
func TestDeliberatelyAbsentCommandsStayAbsent(t *testing.T) {
	for _, name := range deliberatelyAbsent {
		if _, present := commands[name]; present {
			t.Errorf("%q is in the whitelist but is listed as deliberately absent — "+
				"one of the two is now wrong", name)
		}
	}
	// panic and disable in particular: both take the LAN offline, and the
	// second takes the dashboard with it.
	for _, name := range []string{"panic", "disable"} {
		if !containsStr(deliberatelyAbsent, name) {
			t.Errorf("%q is no longer recorded as deliberately absent", name)
		}
	}
}

// Nothing from a request is ever appended except a value the command's own
// validator accepted.
func TestArgumentsAreValidatedNotForwarded(t *testing.T) {
	h := newHandler(t)

	// A command that takes none must refuse any.
	if resp := h.Handle(Request{Action: "run_command", Command: "status", Args: []string{"--help"}}); resp.OK {
		t.Error("status accepted an argument")
	}

	// One that takes an IP must refuse anything else.
	for _, arg := range []string{"not-an-ip", "192.168.1.5; reboot", "--config=/etc/shadow", "$(id)"} {
		if resp := h.Handle(Request{Action: "run_command", Command: "diag", Args: []string{arg}}); resp.OK {
			t.Errorf("diag accepted %q", arg)
		}
	}

	// And more than one is refused outright.
	if resp := h.Handle(Request{Action: "run_command", Command: "diag",
		Args: []string{"192.168.1.5", "extra"}}); resp.OK {
		t.Error("diag accepted two arguments")
	}
}

func TestHoursArgumentIsBounded(t *testing.T) {
	h := newHandler(t)
	for _, arg := range []string{"0", "-1", "9999", "abc", "24h"} {
		if resp := h.Handle(Request{Action: "run_command", Command: "history", Args: []string{arg}}); resp.OK {
			t.Errorf("history accepted %q hours", arg)
		}
	}
	if err := validateHours("48"); err != nil {
		t.Errorf("a reasonable value was refused: %v", err)
	}
}

// Every command must declare a timeout, or a hung one holds the helper open
// until the web process gives up on it.
func TestEveryCommandIsBounded(t *testing.T) {
	for name, c := range commands {
		if c.Timeout <= 0 {
			t.Errorf("%s has no timeout", name)
		}
		if len(c.Args) == 0 {
			t.Errorf("%s has no arguments, so it would run bare gw", name)
		}
		if c.Name != name {
			t.Errorf("%s is keyed as %q but named %q", name, name, c.Name)
		}
	}
}

// The commands that interrupt service are marked, so the UI can confirm them.
func TestDisruptiveCommandsAreMarked(t *testing.T) {
	for _, name := range []string{"apply", "restart", "check-killswitch", "bench",
		"update-services", "update-xray", "update-adguard"} {
		c, ok := commands[name]
		if !ok {
			t.Fatalf("%s is missing from the whitelist", name)
		}
		if !c.Disruptive {
			t.Errorf("%s interrupts service but is not marked disruptive", name)
		}
	}
	for _, name := range []string{"status", "diff", "render", "version", "logs", "update-check"} {
		if c := commands[name]; c.Disruptive {
			t.Errorf("%s changes nothing but is marked disruptive, which trains people "+
				"to click through the confirmation", name)
		}
	}
}

// A non-zero exit is a result, not a transport failure: `gw check` exits 1 when
// a check fails, and its output is the entire point.
func TestFailingCommandStillReturnsItsOutput(t *testing.T) {
	h := newHandler(t)
	// No bin/gw in the test repo, so this exercises the missing-binary path,
	// which must also explain itself rather than returning an empty failure.
	resp := h.Handle(Request{Action: "run_command", Command: "status"})
	if resp.OK {
		t.Skip("bin/gw exists in the test repo")
	}
	if !strings.Contains(resp.Error, "not built") {
		t.Errorf("the error does not say what is missing: %q", resp.Error)
	}
}

func TestCommandListIsOffered(t *testing.T) {
	h := newHandler(t)
	resp := h.Handle(Request{Action: "commands"})
	if !resp.OK {
		t.Fatalf("%s", resp.Error)
	}
	list, _ := resp.Data["commands"].([]Command)
	if len(list) < 10 {
		t.Errorf("only %d commands offered", len(list))
	}
	for _, c := range list {
		if c.Summary == "" {
			t.Errorf("%s has no summary, so the UI cannot say what it does", c.Name)
		}
	}
	excluded, _ := resp.Data["excluded"].([]string)
	if len(excluded) == 0 {
		t.Error("the excluded list is not offered, so the UI cannot explain the gaps")
	}
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
