package transport

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
)

type Local struct{}

func NewLocal() *Local { return &Local{} }

func (l *Local) Description() string { return "local" }

func (l *Local) Run(ctx context.Context, request Request) (Result, error) {
	args := []string{"-ceu", request.Script}
	program := "sh"
	if request.Privileged && os.Geteuid() != 0 {
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

func (l *Local) ReadFile(ctx context.Context, path string) (string, error) {
	result, err := l.Run(ctx, Request{Script: "cat -- " + ShellQuote(path)})
	return result.Stdout, err
}

func (l *Local) FileExists(ctx context.Context, path string) (bool, error) {
	_, err := l.Run(ctx, Request{Script: "test -e -- " + ShellQuote(path)})
	if err == nil {
		return true, nil
	}
	if _, ok := err.(*ExitError); ok {
		return false, nil
	}
	return false, err
}
