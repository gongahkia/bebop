// Package transport isolates host operations from the planner and modules.
package transport

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
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

// ApplyLocker is optional so existing test and third-party transports remain
// valid. Built-in local and SSH transports implement it with a target-side
// flock lease held for the full mutation window.
type ApplyLocker interface {
	AcquireApplyLock(context.Context) (ApplyLock, error)
}

type ApplyLock interface {
	Release() error
}

type LockError struct {
	Busy bool
	Err  error
}

func (e *LockError) Error() string {
	if e.Busy {
		return "another Bebop apply already holds the target lock"
	}
	if e.Err != nil {
		return "acquire Bebop target lock: " + e.Err.Error()
	}
	return "acquire Bebop target lock"
}

func (e *LockError) Unwrap() error { return e.Err }

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

const defaultApplyLockPath = "/run/lock/bebop.lock"

func lockScript(path string) string {
	return "exec 9>" + ShellQuote(path) + "\nflock -n 9 || exit 75\nprintf 'bebop-lock-acquired\\n'\ncat >/dev/null"
}

func acquireProcessLock(ctx context.Context, program string, arguments []string) (ApplyLock, error) {
	command := exec.CommandContext(ctx, program, arguments...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return nil, &LockError{Err: err}
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, &LockError{Err: err}
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		return nil, &LockError{Err: err}
	}
	lease := &processLock{stdin: stdin, done: make(chan error, 1)}
	go func() { lease.done <- command.Wait() }()
	line, readErr := bufio.NewReader(stdout).ReadString('\n')
	if readErr == nil && line == "bebop-lock-acquired\n" {
		return lease, nil
	}
	_ = stdin.Close()
	waitErr := <-lease.done
	if exitCode(waitErr) == 75 {
		return nil, &LockError{Busy: true, Err: waitErr}
	}
	if readErr != nil {
		return nil, &LockError{Err: fmt.Errorf("wait for lock lease: %w", readErr)}
	}
	return nil, &LockError{Err: fmt.Errorf("lock lease did not acknowledge acquisition: %s", strings.TrimSpace(stderr.String()))}
}

type processLock struct {
	stdin io.WriteCloser
	done  chan error
	once  sync.Once
	err   error
}

func (lease *processLock) Release() error {
	lease.once.Do(func() {
		_ = lease.stdin.Close()
		lease.err = <-lease.done
	})
	return lease.err
}

func exitCode(err error) int {
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 0
}

// POSIX shell test does not consistently accept GNU-style --. The path is
// passed as one quoted shell word, and a relative leading-dash path is made
// explicit with ./ so it cannot be interpreted as a test operand option.
func fileExistsScript(path string) string {
	quoted := ShellQuote(path)
	return "path=" + quoted + "\ncase \"$path\" in -*) test -e \"./$path\";; *) test -e \"$path\";; esac"
}
