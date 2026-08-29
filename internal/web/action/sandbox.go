package action

import (
	"fmt"
	"os"
	"os/exec"
)

// nsReexecEnv marks a process that has already re-entered PID 1's namespace,
// so the escape happens at most once.
const nsReexecEnv = "GW_NS_REEXEC"

// EscapeServiceSandbox leaves gw-web's mount namespace before touching the
// filesystem.
//
// gw-web.service runs with ProtectSystem=strict, and a sudo'd child inherits
// that mount namespace — so this helper is root and still sees a read-only /opt
// and /etc:
//
//	open /opt/gateway/gateway.toml: read-only file system
//
// That sandbox exists to stop the *web process* writing anything directly; it
// was never meant to constrain the privileged helper, which is the whole
// sanctioned path for making changes. Re-enter PID 1's namespace once, then
// carry on. Run from a shell, the namespaces already match and this is a no-op.
//
// The dashboard normally reaches the helper via systemd-run, which starts it as
// a fresh transient unit outside the sandbox entirely; this covers the fallback
// path where systemd-run is unavailable.
func EscapeServiceSandbox(args []string) error {
	if os.Getenv(nsReexecEnv) != "" {
		return nil
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		// Cannot tell. Carry on and let the real error speak — refusing here
		// would break the helper on any system without that file.
		return nil
	}
	init, err := os.Readlink("/proc/1/ns/mnt")
	if err != nil || self == init {
		return nil
	}

	nsenter, err := exec.LookPath("nsenter")
	if err != nil {
		return fmt.Errorf("running inside a service sandbox and nsenter is not " +
			"available — install util-linux, or run this from a shell")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// execve keeps stdin, so the JSON request on it survives the re-exec.
	if err := os.Chdir("/"); err != nil {
		return err
	}
	argv := append([]string{nsenter, "--mount=/proc/1/ns/mnt", "--", exe}, args...)
	env := append(os.Environ(), nsReexecEnv+"=1")
	return syscallExec(nsenter, argv, env)
}
