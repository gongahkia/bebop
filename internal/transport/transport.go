// Package transport isolates host operations from the planner and modules.
package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Request executes a Bebop-controlled POSIX shell script. Callers must use
// ShellQuote for every dynamic value; no caller passes user input as shell code.
type Request struct {
	Script     string
	Stdin      []byte
	Privileged bool
}

type Result struct {
	Stdout   string
	Stderr   string
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
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	if e.Stderr == "" {
		return fmt.Sprintf("command exited with status %d", e.Code)
	}
	return fmt.Sprintf("command exited with status %d: %s", e.Code, e.Stderr)
}

// FailureKind gives the control plane a useful diagnostic category without
// requiring it to parse a platform-specific ssh exit status at every callsite.
type FailureKind string

const (
	FailureUnknown            FailureKind = "unknown"
	FailureDNS                FailureKind = "dns"
	FailureTimeout            FailureKind = "timeout"
	FailureRefused            FailureKind = "connection_refused"
	FailureHostKey            FailureKind = "host_key"
	FailureAuthentication     FailureKind = "authentication"
	FailureSSHClient          FailureKind = "ssh_client"
	FailureSudoUnavailable    FailureKind = "sudo_unavailable"
	FailureSudoAuthentication FailureKind = "sudo_authentication_required"
	FailureRemoteCommand      FailureKind = "remote_command"
)

// ClassifyFailure makes a best-effort classification from OpenSSH and sudo's
// stable diagnostic wording while preserving the original error for debugging.
func ClassifyFailure(err error) FailureKind {
	if err == nil {
		return FailureUnknown
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return FailureTimeout
	}
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "could not resolve hostname"), strings.Contains(text, "name or service not known"), strings.Contains(text, "temporary failure in name resolution"):
		return FailureDNS
	case strings.Contains(text, "connection timed out"), strings.Contains(text, "operation timed out"), strings.Contains(text, "i/o timeout"):
		return FailureTimeout
	case strings.Contains(text, "connection refused"):
		return FailureRefused
	case strings.Contains(text, "host key verification failed"), strings.Contains(text, "remote host identification has changed"):
		return FailureHostKey
	case strings.Contains(text, "permission denied"), strings.Contains(text, "authentication failed"), strings.Contains(text, "too many authentication failures"):
		return FailureAuthentication
	case strings.Contains(text, "executable file not found"), strings.Contains(text, "ssh client"):
		return FailureSSHClient
	case strings.Contains(text, "a password is required"), strings.Contains(text, "no tty present and no askpass"):
		return FailureSudoAuthentication
	case strings.Contains(text, "sudo: not found"), strings.Contains(text, "command not found: sudo"):
		return FailureSudoUnavailable
	default:
		return FailureRemoteCommand
	}
}
