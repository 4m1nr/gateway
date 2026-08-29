package config

import "fmt"

// Error is a user-facing configuration problem. Every message here is meant to
// be read by someone editing gateway.toml at 1am with the LAN down, so they say
// what is wrong, where, and what to write instead.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }

func errf(format string, a ...any) *Error {
	return &Error{msg: fmt.Sprintf(format, a...)}
}
