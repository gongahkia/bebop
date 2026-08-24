package transport

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/bebop-home/bebop/internal/target"
)

// SSH uses the system OpenSSH client so existing SSH configuration, identities,
// host keys, and known_hosts behaviour remain in force. BatchMode deliberately
// rejects password prompts; Bebop never handles SSH or sudo passwords.
type SSH struct{ target target.Target }

func NewSSH(t target.Target) *SSH { return &SSH{target: t} }

func (s *SSH) Description() string { return s.target.String() }

func (s *SSH) Run(ctx context.Context, request Request) (Result, error) {
	args := s.commandArgs(request)
	command := exec.CommandContext(ctx, "ssh", args...)
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

func (s *SSH) commandArgs(request Request) []string {
	args := []string{"-o", "BatchMode=yes"}
	if s.target.Port != 0 {
		args = append(args, "-p", stringPort(s.target.Port))
	}
	args = append(args, s.target.User+"@"+s.target.Host)
	remote := "sh -ceu " + ShellQuote(request.Script)
	if request.Privileged {
		remote = "if test \"$(id -u)\" -eq 0; then sh -ceu " + ShellQuote(request.Script) + "; else exec sudo -n sh -ceu " + ShellQuote(request.Script) + "; fi"
	}
	return append(args, remote)
}

func (s *SSH) ReadFile(ctx context.Context, path string) (string, error) {
	result, err := s.Run(ctx, Request{Script: "cat -- " + ShellQuote(path)})
	return result.Stdout, err
}

func (s *SSH) FileExists(ctx context.Context, path string) (bool, error) {
	_, err := s.Run(ctx, Request{Script: "test -e -- " + ShellQuote(path)})
	if err == nil {
		return true, nil
	}
	if _, ok := err.(*ExitError); ok {
		return false, nil
	}
	return false, err
}

func (s *SSH) AcquireApplyLock(ctx context.Context) (ApplyLock, error) {
	args := []string{"-o", "BatchMode=yes"}
	if s.target.Port != 0 {
		args = append(args, "-p", stringPort(s.target.Port))
	}
	args = append(args, s.target.User+"@"+s.target.Host)
	script := lockScript(defaultApplyLockPath)
	remote := "if test \"$(id -u)\" -eq 0; then exec sh -ceu " + ShellQuote(script) + "; else exec sudo -n sh -ceu " + ShellQuote(script) + "; fi"
	args = append(args, remote)
	return acquireProcessLock(ctx, "ssh", args)
}

func stringPort(port int) string {
	if port == 0 {
		return ""
	}
	return strconv.Itoa(port)
}
