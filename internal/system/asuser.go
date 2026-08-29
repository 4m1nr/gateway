package system

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
	"time"
)

// AsUser builds a command that runs as another account.
//
// Running as the xray user is how the box reaches the internet without the
// tunnel: the output chain returns early on that uid, so its traffic is never
// intercepted. That is what makes "what is my real IP" and "how fast is the
// link without the tunnel" answerable at all.
//
// Go can set the credentials directly rather than shelling out to setpriv or
// runuser, which is what the bash had to do — and which had its own fallback
// chain because runuser moved to util-linux-extra in Debian 12 and is absent
// from a minimal install. None of that is needed here.
func AsUser(ctx context.Context, username string, name string, args ...string) (*exec.Cmd, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return nil, fmt.Errorf("no such user: %s", username)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return nil, fmt.Errorf("user %s has a non-numeric uid", username)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		gid = uid
	}

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
			// No supplementary groups: the point is to be exactly that user,
			// and inheriting root's groups would defeat it.
			Groups:      []uint32{},
			NoSetGroups: false,
		},
	}
	return cmd, nil
}

// RunAsUser runs a command as another account and returns its stdout.
func RunAsUser(username string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd, err := AsUser(ctx, username, name, args...)
	if err != nil {
		return "", err
	}
	out, err := cmd.Output()
	return string(out), err
}
