package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestJSONCommandShapesAgainstReadOnlyFakeTarget(t *testing.T) {
	fake := &cliFakeTransport{}
	service := bebop.NewService()
	service.TransportFactory = func(target.Target) (transport.Transport, error) { return fake, nil }
	for _, invocation := range [][]string{{"inspect", "--json"}, {"status", "--json"}, {"doctor", "--json"}} {
		var stdout, stderr bytes.Buffer
		runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
		if code := runner.Run(invocation); code != 0 {
			t.Fatalf("%v failed: %d stderr=%s", invocation, code, stderr.String())
		}
		var value map[string]any
		if err := json.Unmarshal(stdout.Bytes(), &value); err != nil {
			t.Fatalf("%v output is not JSON: %v\n%s", invocation, err, stdout.String())
		}
	}
	configPath := filepath.Join(t.TempDir(), "bebop.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"plan", "--config", configPath, "--json"}); code != 0 {
		t.Fatalf("plan failed: %d %s", code, stderr.String())
	}
	var planned struct {
		Changes     []any  `json:"changes"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &planned); err != nil {
		t.Fatal(err)
	}
	if len(planned.Changes) != 0 || planned.Fingerprint == "" {
		t.Fatalf("unexpected converged plan: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"apply", "--config", configPath, "--json", "--yes"}); code != 0 {
		t.Fatalf("converged JSON apply failed: %d %s", code, stderr.String())
	}
	var applied struct {
		Plan   map[string]any `json:"plan"`
		Result map[string]any `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &applied); err != nil || applied.Plan == nil || applied.Result == nil {
		t.Fatalf("converged JSON apply shape: %v\n%s", err, stdout.String())
	}
	if fake.privileged {
		t.Fatal("read-only commands unexpectedly requested privilege")
	}
}

func TestInitWritesLocalStarterWithoutMutatingTarget(t *testing.T) {
	fake := &cliFakeTransport{}
	service := bebop.NewService()
	service.TransportFactory = func(target.Target) (transport.Transport, error) { return fake, nil }
	output := filepath.Join(t.TempDir(), "bebop.toml")
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"init", "--output", output}); code != 0 {
		t.Fatalf("init failed: %d %s", code, stderr.String())
	}
	contents, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "version = 1") || fake.privileged {
		t.Fatalf("init output=%s privileged=%t", contents, fake.privileged)
	}
}

func TestHostCommandsAndAliasPlanUseInventoryConfig(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "bebop.hosts.toml")
	configPath := filepath.Join(filepath.Dir(inventoryPath), "hosts", "pi.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &cliFakeTransport{}
	service := bebop.NewService()
	service.TransportFactory = func(target.Target) (transport.Transport, error) { return fake, nil }
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"host", "add", "pi", "--inventory", inventoryPath, "--target", "ssh://pi@home", "--config", "hosts/pi.toml"}); code != 0 {
		t.Fatalf("host add failed: %d %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"host", "list", "--inventory", inventoryPath, "--json"}); code != 0 || !strings.Contains(stdout.String(), `"name": "pi"`) {
		t.Fatalf("host list failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"plan", "pi", "--inventory", inventoryPath, "--json"}); code != 0 {
		t.Fatalf("alias plan failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"host", "remove", "pi", "--inventory", inventoryPath}); code == 0 {
		t.Fatal("host removal unexpectedly skipped explicit confirmation")
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"host", "remove", "pi", "--inventory", inventoryPath, "--yes"}); code != 0 {
		t.Fatalf("host remove failed: %d %s", code, stderr.String())
	}
}

func TestPortablePlanCanBeWrittenAndAppliedWithFreshPlanSemantics(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "bebop.toml")
	artifactPath := filepath.Join(t.TempDir(), "pi.plan.json")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &cliFakeTransport{}
	service := bebop.NewService()
	service.TransportFactory = func(target.Target) (transport.Transport, error) { return fake, nil }
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"plan", "--config", configPath, "--out", artifactPath, "--json"}); code != 0 {
		t.Fatalf("saved plan creation failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(artifactPath); err != nil {
		t.Fatalf("saved plan was not written: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"apply", "--plan", artifactPath, "--yes", "--json"}); code != 0 {
		t.Fatalf("saved plan apply failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	contents, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifactPath, bytes.Replace(contents, []byte(`"target": "local"`), []byte(`"target": "ssh://pi@other"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"apply", "--plan", artifactPath, "--yes", "--json"}); code == 0 || !strings.Contains(stderr.String(), "does not match") {
		t.Fatalf("tampered saved plan was accepted: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestFleetReadCommandsKeepSuccessfulHostsWhenOneFails(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "bebop.hosts.toml")
	if err := inventory.WriteFile(inventoryPath, inventory.Inventory{Version: inventory.CurrentVersion, Hosts: map[string]inventory.Host{
		"bad": {Target: "ssh://pi@bad"},
		"pi":  {Target: "ssh://pi@pi"},
	}}); err != nil {
		t.Fatal(err)
	}
	service := bebop.NewService()
	service.TransportFactory = func(current target.Target) (transport.Transport, error) {
		if current.Host == "bad" {
			return nil, errors.New("connection refused")
		}
		return &cliFakeTransport{}, nil
	}
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"status", "--all", "--inventory", inventoryPath, "--parallel", "2"}); code == 0 {
		t.Fatalf("mixed fleet status unexpectedly succeeded: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "bad") || !strings.Contains(stdout.String(), "pi") || strings.Index(stdout.String(), "bad") > strings.Index(stdout.String(), "pi") {
		t.Fatalf("fleet status omitted or reordered results: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"doctor", "--all", "--inventory", inventoryPath, "--json", "--parallel", "2"}); code == 0 {
		t.Fatalf("mixed fleet doctor unexpectedly succeeded: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
	var report struct {
		Hosts []struct {
			Host  string `json:"host"`
			Error string `json:"error"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || len(report.Hosts) != 2 || report.Hosts[0].Host != "bad" || report.Hosts[0].Error == "" || report.Hosts[1].Host != "pi" {
		t.Fatalf("fleet doctor JSON lost per-host results: %#v err=%v output=%s", report, err, stdout.String())
	}
}

type cliFakeTransport struct{ privileged bool }

func (f *cliFakeTransport) Description() string                              { return "fake" }
func (f *cliFakeTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (f *cliFakeTransport) ReadFile(_ context.Context, path string) (string, error) {
	if path == "/etc/os-release" {
		return "NAME=Debian\nID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n", nil
	}
	return "", nil
}
func (f *cliFakeTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	if request.Privileged {
		f.privileged = true
	}
	script := request.Script
	switch {
	case script == "hostname":
		return transport.Result{Stdout: "home\n"}, nil
	case script == "uname -m":
		return transport.Result{Stdout: "aarch64\n"}, nil
	case script == "uname -r":
		return transport.Result{Stdout: "6.1\n"}, nil
	case script == "id -un":
		return transport.Result{Stdout: "pi\n"}, nil
	case strings.Contains(script, "command -v sudo"):
		return transport.Result{Stdout: "yes"}, nil
	case strings.Contains(script, "command -v systemctl"):
		return transport.Result{Stdout: "yes"}, nil
	case strings.Contains(script, "command -v apt-get"):
		return transport.Result{Stdout: "apt"}, nil
	case strings.Contains(script, "command -v sshd"):
		return transport.Result{Stdout: "installed=yes\nservice=ssh.service\nenabled=yes\nactive=yes\nvalid=yes\ndropin=yes\nfirst=00-bebop.conf\neffective=yes\nkeys=yes\n"}, nil
	case strings.Contains(script, "test -r /etc/ssh/sshd_config.d/00-bebop.conf"):
		return transport.Result{Stdout: modules.SSHDropIn}, nil
	case strings.Contains(script, "tailscale status --json"):
		return transport.Result{Stdout: `{"BackendState":"Running","Self":{"Online":true}}`}, nil
	case strings.Contains(script, "tailscale 2>/dev/null"):
		return transport.Result{Stdout: "installed=yes\nenabled=yes\nactive=yes\n"}, nil
	case strings.Contains(script, "docker.io"):
		return transport.Result{Stdout: "installed=yes\nenabled=yes\nactive=yes\nresponsive=yes\n"}, nil
	case strings.Contains(script, "unattended-upgrades"):
		return transport.Result{Stdout: "installed=yes\nenabled=yes\n"}, nil
	case strings.Contains(script, "command -v ufw"):
		return transport.Result{Stdout: "ufw=no\nactive=no\nother=no\n"}, nil
	case strings.Contains(script, "MemTotal"):
		return transport.Result{Stdout: "1048576"}, nil
	case strings.Contains(script, "findmnt"):
		return transport.Result{Stdout: "/dev/root ext4 10G 8G"}, nil
	case strings.Contains(script, "stat -c"):
		return transport.Result{Stdout: "750 0 0"}, nil
	case strings.Contains(script, "test -w"):
		return transport.Result{Stdout: "no"}, nil
	default:
		return transport.Result{}, nil
	}
}
