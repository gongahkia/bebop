package transport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/target"
)

func TestLocalRunOutputExitAndCancellation(t *testing.T) {
	local := NewLocal()
	result, err := local.Run(context.Background(), Request{Script: "printf hello"})
	if err != nil || result.Stdout != "hello" {
		t.Fatalf("stdout: %#v %v", result, err)
	}
	result, err = local.Run(context.Background(), Request{Script: "echo failure >&2; exit 7"})
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != 7 || !strings.Contains(result.Stderr, "failure") {
		t.Fatalf("exit propagation: %#v %v", result, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = local.Run(ctx, Request{Script: "sleep 1"})
	if err == nil {
		t.Fatal("expected cancellation")
	}
}

func TestShellQuoteAndSSHArgumentConstruction(t *testing.T) {
	value := "a'; touch /not-run; echo 'b"
	result, err := NewLocal().Run(context.Background(), Request{Script: "printf %s " + ShellQuote(value)})
	if err != nil || result.Stdout != value {
		t.Fatalf("quote failed: %#v %v", result, err)
	}
	parsed, err := target.Parse("ssh://pi@host.example:2200")
	if err != nil {
		t.Fatal(err)
	}
	ssh := NewSSH(parsed)
	args := ssh.commandArgs(Request{Script: "printf %s " + ShellQuote(value), Privileged: true})
	if args[0] != "-o" || args[1] != "BatchMode=yes" || args[3] != "2200" || args[4] != "pi@host.example" {
		t.Fatalf("unexpected SSH args: %#v", args)
	}
	if !strings.Contains(args[len(args)-1], ShellQuote("printf %s "+ShellQuote(value))) || !strings.Contains(args[len(args)-1], "sudo -n") {
		t.Fatalf("unsafe remote command: %q", args[len(args)-1])
	}
}

func TestClassifyFailure(t *testing.T) {
	for _, test := range []struct {
		err  error
		want FailureKind
	}{
		{errors.New("ssh: Could not resolve hostname pi: Name or service not known"), FailureDNS},
		{errors.New("ssh: connect to host pi port 22: Connection refused"), FailureRefused},
		{errors.New("Host key verification failed."), FailureHostKey},
		{errors.New("Permission denied (publickey)."), FailureAuthentication},
		{context.DeadlineExceeded, FailureTimeout},
		{errors.New("sudo: a password is required"), FailureSudoAuthentication},
	} {
		if got := ClassifyFailure(test.err); got != test.want {
			t.Fatalf("ClassifyFailure(%q) = %q, want %q", test.err, got, test.want)
		}
	}
}
