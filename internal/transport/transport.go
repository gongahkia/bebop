// Package transport isolates host operations from the planner and modules.
package transport

import (
	"context"
	"fmt"
)

// Request executes a Bebop-controlled POSIX shell script. Callers must use
// ShellQuote for every dynamic value; no caller passes user input as shell code.
type Request struct {
	Script string
	Stdin []byte
	Privileged bool
}

type Result struct {
	Stdout string
	Stderr string
	ExitCode int
}

// Transport deliberately has a small surface. Both local and SSH execution
// receive the same script bytes and preserve cancellation and exit status.
type Transport interface {
	Run(context.Context, Request) (Result, error)
	ReadFile(context.Context, string) (string, error)
	FileExists(context.Context, string) (bool, error)
	Description() string
}

// ExitError means the remote command ran but returned a non-zero status.
type ExitError struct {
	Code int
	Stderr string
}

func (e *ExitError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("command exited with status %d", e.Code)
	}
	return fmt.Sprintf("command exited with status %d: %s", e.Code, e.Stderr)
}
