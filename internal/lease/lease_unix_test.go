//go:build !windows

package lease

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLeaseReleasedAfterAbruptProcessDeath(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "job.lock")
	command := exec.Command(os.Args[0], "-test.run=TestLeaseHolderProcess")
	command.Env = append(os.Environ(), "BEBOP_TEST_LEASE_HOLDER=1", "BEBOP_TEST_LEASE_PATH="+filename)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "ready" {
		_ = command.Process.Kill()
		t.Fatalf("lock holder did not become ready: %q", scanner.Text())
	}
	if _, err := Acquire(filename); !errors.Is(err, ErrHeld) {
		_ = command.Process.Kill()
		t.Fatalf("concurrent lease err = %v, want held", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	lease, err := Acquire(filename)
	if err != nil {
		t.Fatalf("lease remained held after abrupt process death: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestLeaseHolderProcess(t *testing.T) {
	if os.Getenv("BEBOP_TEST_LEASE_HOLDER") != "1" {
		return
	}
	lease, err := Acquire(os.Getenv("BEBOP_TEST_LEASE_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	fmt.Fprintln(os.Stdout, "ready")
	select {}
}
