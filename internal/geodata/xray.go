package geodata

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// runXrayTest asks the installed Xray whether it accepts the live config with
// the new data in place. This is the check that turns a bad download into a
// rollback rather than an outage at the next restart.
func runXrayTest() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/local/bin/xray",
		"run", "-test", "-config", XrayConfig).CombinedOutput()
	if err != nil {
		return fmt.Errorf("xray rejected the new geodata: %w\n%s", err, out)
	}
	return nil
}
