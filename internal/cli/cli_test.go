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

	"github.com/bebop-home/bebop/internal/artifact"
	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/plan"
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

func TestMaintenancePolicyCommandsAreControllerLocalAndJSONSafe(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "bebop.toml")
	contents := `version = 1
[maintenance]
version = 1

[[maintenance.jobs]]
name = "disabled-doctor"
type = "doctor"
target = "local"
enabled = false
schedule = "daily@03:00"
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: bebop.NewService(), In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"maintenance", "list", "--config", configPath, "--json"}); code != 0 || !strings.Contains(stdout.String(), `"disabled-doctor"`) {
		t.Fatalf("maintenance list failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, ".bebop", "history")); !os.IsNotExist(err) {
		t.Fatalf("read-only maintenance list created history: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"maintenance", "run", "disabled-doctor", "--config", configPath, "--json"}); code != 0 {
		t.Fatalf("disabled maintenance run failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var record struct {
		Result string `json:"result"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &record); err != nil || record.Result != "skipped" {
		t.Fatalf("disabled maintenance result = %#v %v output=%s", record, err, stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"maintenance", "history", "disabled-doctor", "--config", configPath, "--json"}); code != 0 || !strings.Contains(stdout.String(), `"result": "skipped"`) {
		t.Fatalf("maintenance history failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

func TestNotificationCLIListsTestsAndKeepsSyntheticEventsOutOfActiveIssues(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "bebop.toml")
	contents := `version = 1

[notifications]
version = 1
enabled = true
state_dir = ".bebop/notifications"
history_max_entries = 10

[[notifications.sinks]]
name = "events"
type = "file"
path = ".bebop/notifications/events.jsonl"

[[notifications.routes]]
name = "ops"
sink = "events"
events = ["maintenance.failed"]
recoveries = true
`
	if err := os.WriteFile(configPath, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := New()
	stdout, stderr := &bytes.Buffer{}, &bytes.Buffer{}
	runner.Out, runner.Err = stdout, stderr
	if code := runner.Run([]string{"notification", "list", "--config", configPath, "--json"}); code != 0 || !strings.Contains(stdout.String(), `"events"`) {
		t.Fatalf("notification list failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"notification", "test", "events", "--config", configPath, "--json"}); code != 0 || !strings.Contains(stdout.String(), `"result": "delivered"`) {
		t.Fatalf("notification test failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"notification", "status", "--config", configPath, "--json"}); code != 0 || !strings.Contains(stdout.String(), `"active_issues": []`) {
		t.Fatalf("notification status failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	contentsBytes, err := os.ReadFile(filepath.Join(directory, ".bebop", "notifications", "events.jsonl"))
	if err != nil || !strings.Contains(string(contentsBytes), `"test":true`) {
		t.Fatalf("test file sink = %q %v", contentsBytes, err)
	}
}

func TestStorageAdoptRecordsObservedMountedFilesystemWithoutTargetMutation(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "bebop.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &storageAdoptTransport{}
	service := bebop.NewService()
	service.TransportFactory = func(target.Target) (transport.Transport, error) { return fake, nil }
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: service, In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"storage", "adopt", "bulk", "local", "--config", configPath, "--mount", "/mnt/bulk"}); code != 0 {
		t.Fatalf("storage adopt failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	contents, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), "[storage.resources.bulk]") || !strings.Contains(string(contents), `filesystem_uuid = "11111111-2222-3333-4444-555555555555"`) || fake.privileged {
		t.Fatalf("adoption did not safely record observed storage: contents=%s privileged=%t", contents, fake.privileged)
	}
}

func TestRecipeCommandsMaterializeAndUpgradeWithoutTargetAccess(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "bebop.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	runner := &Runner{Service: bebop.NewService(), In: strings.NewReader(""), Out: &stdout, Err: &stderr}
	if code := runner.Run([]string{"recipe", "list", "--json"}); code != 0 || !strings.Contains(stdout.String(), `"vaultwarden"`) {
		t.Fatalf("recipe list failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"recipe", "init", "vaultwarden", "--service", "passwords", "--config", configPath, "--secret-file", "secrets/passwords.env", "--dry-run", "--json"}); code != 0 || !strings.Contains(stdout.String(), `"secret_example": "secrets/passwords.env.example"`) {
		t.Fatalf("recipe secret dry run failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "services", "passwords")); !os.IsNotExist(err) {
		t.Fatalf("recipe dry run wrote service source: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"recipe", "init", "whoami", "--version", "1.0.0", "--service", "echo", "--param", "port=8181", "--config", configPath, "--json"}); code != 0 {
		t.Fatalf("recipe init failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "services", "echo", "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	configContents, err := os.ReadFile(configPath)
	if err != nil || !strings.Contains(string(configContents), "[services.echo]") {
		t.Fatalf("recipe init did not append ordinary service config: %s %v", configContents, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := runner.Run([]string{"recipe", "upgrade", "echo", "--to", "1.1.0", "--config", configPath, "--json"}); code != 0 {
		t.Fatalf("recipe upgrade failed: %d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	compose, err := os.ReadFile(filepath.Join(root, "services", "echo", "compose.yaml"))
	if err != nil || !strings.Contains(string(compose), "bebop.recipe.revision") || !strings.Contains(string(compose), "8181:80") {
		t.Fatalf("recipe upgrade output invalid: %s %v", compose, err)
	}
	if code := runner.Run([]string{"recipe", "init", "whoami", "--service", "../../escape", "--config", configPath}); code == 0 {
		t.Fatal("recipe output traversal was accepted")
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

func TestOperationalErrorCategoriesHaveDistinctExitCodes(t *testing.T) {
	for _, test := range []struct {
		code errs.Code
		want int
	}{
		{errs.ConfigInvalid, 2},
		{errs.TargetUnreachable, 3},
		{errs.PlanStale, 4},
		{errs.ApplyLocked, 5},
	} {
		if got := exitCode(errs.New(test.code, "test", nil)); got != test.want {
			t.Fatalf("code %s exits %d, want %d", test.code, got, test.want)
		}
	}
}

func TestSavedPlanRejectsInventoryAliasRetargeting(t *testing.T) {
	inventoryPath := filepath.Join(t.TempDir(), "bebop.hosts.toml")
	if err := inventory.WriteFile(inventoryPath, inventory.Inventory{Version: inventory.CurrentVersion, Hosts: map[string]inventory.Host{
		"pi": {Target: "ssh://pi@different-host"},
	}}); err != nil {
		t.Fatal(err)
	}
	err := validateSavedInventory(artifact.Artifact{HostAlias: "pi", Target: "ssh://pi@reviewed-host"}, inventoryPath)
	var categorized *errs.Error
	if !errors.As(err, &categorized) || categorized.Code != errs.TargetIdentityMismatch {
		t.Fatalf("retargeted alias was not rejected: %v", err)
	}
}

func TestHumanPlanRenderingUsesShortFingerprint(t *testing.T) {
	var output bytes.Buffer
	renderPlan(&output, plan.Plan{Target: "local", Fingerprint: "0123456789abcdef"}, false)
	if !strings.Contains(output.String(), "Plan fingerprint: 0123456789ab") || strings.Contains(output.String(), "0123456789abcdef") {
		t.Fatalf("human fingerprint was not shortened: %s", output.String())
	}
}

type cliFakeTransport struct{ privileged bool }

type storageAdoptTransport struct{ cliFakeTransport }

func (f *storageAdoptTransport) Run(ctx context.Context, request transport.Request) (transport.Result, error) {
	if strings.Contains(request.Script, "lsblk --json") {
		return transport.Result{Stdout: `{"blockdevices":[{"name":"vdb","path":"/dev/vdb","type":"disk","size":8388608,"children":[{"name":"vdb1","path":"/dev/vdb1","type":"part","size":8388608,"fstype":"ext4","uuid":"11111111-2222-3333-4444-555555555555","mountpoints":["/mnt/bulk"]}]}]}`}, nil
	}
	if strings.Contains(request.Script, "findmnt --json") {
		return transport.Result{Stdout: `{"filesystems":[{"target":"/","source":"/dev/root","fstype":"ext4","options":"rw","size":8388608,"avail":4194304},{"target":"/mnt/bulk","source":"/dev/vdb1","fstype":"ext4","options":"rw","size":8388608,"avail":4194304}]}`}, nil
	}
	return f.cliFakeTransport.Run(ctx, request)
}

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
