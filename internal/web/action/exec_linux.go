package action

import "syscall"

// syscallExec replaces this process. It does not return on success, which is
// what keeps the request on stdin attached to the new image.
func syscallExec(path string, argv, env []string) error {
	return syscall.Exec(path, argv, env)
}
