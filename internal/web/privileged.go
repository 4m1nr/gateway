package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/am1nr/gateway/internal/web/action"
)

// ActionHelperPath is where `gw apply` installs the privileged helper: a copy
// of the gw binary, root-owned, outside the repo. The sudoers grant names this
// exact path with no arguments and no wildcards, so a compromised web process
// cannot ask for anything the helper does not already implement.
const ActionHelperPath = "/usr/local/lib/gateway/gw-action"

// Caller performs one privileged action.
//
// An interface so the HTTP layer can be tested against a substitute: every
// gate in this package must be verifiable without root, sudo, or a gateway.
type Caller interface {
	Call(action.Request) (action.Response, error)
}

// SudoCaller runs an action through the root helper.
type SudoCaller struct {
	// HelperPath overrides ActionHelperPath, for tests.
	HelperPath string
	// Timeout bounds the call. `apply` is the slow one and can legitimately
	// take minutes on a thin client.
	Timeout time.Duration
}

func (p SudoCaller) helper() string {
	if p.HelperPath != "" {
		return p.HelperPath
	}
	return ActionHelperPath
}

func (p SudoCaller) timeout() time.Duration {
	if p.Timeout == 0 {
		return 310 * time.Second
	}
	return p.Timeout
}

// Call hands a request to the root helper and decodes its reply.
//
// systemd-run is tried first, so PID 1 spawns the helper as a fresh transient
// unit. A plain sudo child stays inside THIS service's sandbox — it inherits
// the mount namespace (ProtectSystem=strict, so /opt and /etc are read-only
// even for root) and the seccomp filter (RestrictNamespaces=true, so it cannot
// escape by itself either). Both restrictions are worth keeping on a
// network-facing process; the helper simply should not be subject to them.
//
// Both forms are named in full in the sudoers file, so this stays an
// exact-command grant with no wildcards.
func (p SudoCaller) Call(req action.Request) (action.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout())
	defer cancel()

	payload, err := json.Marshal(req)
	if err != nil {
		return action.Response{}, fmt.Errorf("encoding the request: %w", err)
	}

	attempts := [][]string{
		{"sudo", "-n", "/usr/bin/systemd-run", "--pipe", "--wait", "--collect", "--quiet", p.helper()},
		{"sudo", "-n", p.helper()},
	}

	last := "the privileged helper failed"
	for _, argv := range attempts {
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Stdin = bytes.NewReader(payload)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		runErr := cmd.Run()

		if out := strings.TrimSpace(stdout.String()); out != "" {
			var resp action.Response
			if json.Unmarshal([]byte(out), &resp) == nil {
				return resp, nil
			}
		}
		if ctx.Err() != nil {
			return action.Response{}, fmt.Errorf("the action timed out")
		}
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			last = msg
		} else if runErr != nil {
			last = fmt.Sprintf("%s exited with %v and produced no output", p.helper(), runErr)
		}
	}
	return action.Response{}, fmt.Errorf("%s", truncate(last, 500))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var _ Caller = SudoCaller{}
