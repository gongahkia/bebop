package transport

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
)

type Local struct {
	lockPath       string
	lockPrivileged bool
}

func NewLocal() *Local { return &Local{lockPath: defaultApplyLockPath, lockPrivileged: true} }

// NewLocalWithLockPath exists for disposable test environments. Production
// callers should use NewLocal and its fixed target-side lock location.
func NewLocalWithLockPath(lockPath string) *Local { return &Local{lockPath: lockPath} }

func (l *Local) Description() string { return "local" }

func (l *Local) Run(ctx context.Context, request Request) (Result, error) {
	args := []string{"-ceu", request.Script}
	program := "sh"
	if request.Privileged && requiresLocalSudo() {
		program = "sudo"
		args = append([]string{"-n", "sh"}, args...)
	}
	command := exec.CommandContext(ctx, program, args...)
	command.Stdin = strings.NewReader(string(request.Stdin))
	var stdout, stderr strings.Builder
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := Result{Stdout: stdout.String(), Stderr: strings.TrimSpace(stderr.String())}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, &ExitError{Code: result.ExitCode, Stderr: result.Stderr}
	}
	return result, err
}

func (l *Local) RunStream(ctx context.Context, request StreamRequest, output io.Writer) (Result, error) {
	args := []string{"-ceu", request.Script}
	program := "sh"
	if request.Privileged && requiresLocalSudo() {
		program = "sudo"
		args = append([]string{"-n", "sh"}, args...)
	}
	command := exec.CommandContext(ctx, program, args...)
	command.Stdin = request.Stdin
	if output == nil {
		output = io.Discard
	}
	command.Stdout = output
	var stderr strings.Builder
	command.Stderr = &stderr
	err := command.Run()
	result := Result{Stderr: strings.TrimSpace(stderr.String())}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, &ExitError{Code: result.ExitCode, Stderr: result.Stderr}
	}
	return result, err
}

func (l *Local) ReadFile(ctx context.Context, path string) (string, error) {
	result, err := l.Run(ctx, Request{Script: "cat -- " + ShellQuote(path)})
	return result.Stdout, err
}

func (l *Local) FileExists(ctx context.Context, path string) (bool, error) {
	_, err := l.Run(ctx, Request{Script: fileExistsScript(path)})
	if err == nil {
		return true, nil
	}
	if _, ok := err.(*ExitError); ok {
		return false, nil
	}
	return false, err
}

func (l *Local) AcquireApplyLock(ctx context.Context) (ApplyLock, error) {
	program := "sh"
	arguments := []string{"-ceu", lockScript(l.lockPath)}
	if l.lockPrivileged && requiresLocalSudo() {
		program = "sudo"
		arguments = append([]string{"-n", "sh"}, arguments...)
	}
	return acquireProcessLock(ctx, program, arguments)
}
