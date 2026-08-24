//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/backup"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/transport"
)

// TestComposeLifecycleAgainstDisposableDind exercises Bebop's real staged
// transfer, Docker Compose validation/reconciliation, health wait, update,
// runtime-drift correction, stop, and volume-preserving removal against a
// privileged nested Docker daemon. It is opt-in and leaves no host Docker
// project, volume, target path, or daemon configuration behind.
func TestComposeLifecycleAgainstDisposableDind(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is required: %v", err)
	}
	target := startDind(t)
	root := t.TempDir()
	writeComposeFixture(t, root, "running", "one")
	cfg := loadComposeFixture(t, root)
	provider := modules.Compose{PollInterval: 50 * time.Millisecond}
	planner := planner.New(provider)
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host := dindHost(cfg, facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	first := buildPlan(t, planner, host, cfg)
	if ids(first) != "service.hello.deploy,service.hello.start" {
		t.Fatalf("unexpected initial plan: %#v", first.Changes)
	}
	runServiceChanges(t, provider, target, cfg, first)
	assertExec(t, target, "test -L /work/bebop/services/hello/current")
	assertExec(t, target, "docker --context default ps --filter label=com.docker.compose.project="+transport.ShellQuote(deployment.Project)+" --format '{{.State}}' | grep -qx running")

	// Runtime drift is distinct from source drift: no deployment action should
	// be needed after a manually stopped container.
	assertExec(t, target, "docker --context default stop $(docker --context default ps --quiet --filter label=com.docker.compose.project="+transport.ShellQuote(deployment.Project)+")")
	host.Services[0].DeploymentPresent = true
	host.Services[0].DeploymentDigest = deployment.SourceDigest
	host.Services[0].Runtime, host.Services[0].Health = "stopped", "stopped"
	drift := buildPlan(t, planner, host, cfg)
	if ids(drift) != "service.hello.start" {
		t.Fatalf("runtime drift did not produce only start: %#v", drift.Changes)
	}
	runServiceChanges(t, provider, target, cfg, drift)

	// A manual edit inside Bebop's active deployment is source drift. The next
	// plan restores declared content before reconciling the still-isolated
	// Compose project.
	assertExec(t, target, "printf '\\n# external deployment drift\\n' >> /work/bebop/services/hello/current/compose.yaml")
	host.Services[0] = facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: targetDeploymentDigest(t, target), Runtime: "running", Health: "healthy"}
	deploymentDrift := buildPlan(t, planner, host, cfg)
	if ids(deploymentDrift) != "service.hello.update,service.hello.start" {
		t.Fatalf("deployment drift did not produce restore/reconcile: %#v", deploymentDrift.Changes)
	}
	runServiceChanges(t, provider, target, cfg, deploymentDrift)
	assertExec(t, target, "! grep -Fq 'external deployment drift' /work/bebop/services/hello/current/compose.yaml")

	// A changed source must create a semantic deployment update, then reconcile
	// only this deterministic Compose project.
	writeComposeFixture(t, root, "running", "two")
	cfg = loadComposeFixture(t, root)
	updated, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host.Services[0] = facts.Service{Name: "hello", Project: updated.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: deployment.SourceDigest, Runtime: "running", Health: "healthy"}
	update := buildPlan(t, planner, host, cfg)
	if ids(update) != "service.hello.update,service.hello.start" {
		t.Fatalf("source change did not produce deploy/start update: %#v", update.Changes)
	}
	runServiceChanges(t, provider, target, cfg, update)
	assertExec(t, target, "grep -Fq 'bebop.integration.version=two' /work/bebop/services/hello/current/compose.yaml")

	writeComposeFixture(t, root, "stopped", "two")
	cfg = loadComposeFixture(t, root)
	stopped, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host.Services[0] = facts.Service{Name: "hello", Project: stopped.Project, DesiredState: "stopped", DeploymentPresent: true, DeploymentDigest: stopped.SourceDigest, Runtime: "running", Health: "healthy"}
	stop := buildPlan(t, planner, host, cfg)
	if ids(stop) != "service.hello.stop" {
		t.Fatalf("unexpected stopped plan: %#v", stop.Changes)
	}
	runServiceChanges(t, provider, target, cfg, stop)
	assertExec(t, target, "! docker --context default ps --quiet --filter label=com.docker.compose.project="+transport.ShellQuote(stopped.Project)+" --filter status=running | grep -q .")

	writeComposeFixture(t, root, "absent", "two")
	cfg = loadComposeFixture(t, root)
	absent, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host.Services[0] = facts.Service{Name: "hello", Project: absent.Project, DesiredState: "absent", DeploymentPresent: true, DeploymentDigest: stopped.SourceDigest, Runtime: "stopped", Health: "stopped"}
	remove := buildPlan(t, planner, host, cfg)
	if ids(remove) != "service.hello.remove" {
		t.Fatalf("unexpected absent plan: %#v", remove.Changes)
	}
	runServiceChanges(t, provider, target, cfg, remove)
	assertExec(t, target, "test ! -e /work/bebop/services/hello/current")
	assertExec(t, target, "docker --context default volume ls --quiet --filter label=com.docker.compose.project="+transport.ShellQuote(absent.Project)+" | grep -q .")
}

// TestBackupRestoreMigrationAgainstDisposableDind proves the M4 boundary with
// two independent Docker targets. The source and destination deliberately use
// different server names, so their Compose runtime-volume names differ while
// the snapshot maps by logical resource identity.
func TestBackupRestoreMigrationAgainstDisposableDind(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	source, destination := startDind(t), startDind(t)
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	writeBackupComposeFixture(t, sourceRoot, "source")
	writeBackupComposeFixture(t, destinationRoot, "destination")
	sourceConfig, destinationConfig := loadComposeFixture(t, sourceRoot), loadComposeFixture(t, destinationRoot)
	sourceConfig.Backup.Destination = filepath.Join(t.TempDir(), "backups")
	provider := modules.Compose{PollInterval: 50 * time.Millisecond}
	sourceDeployment, err := services.ResolveOne(sourceConfig, "hello")
	if err != nil {
		t.Fatal(err)
	}
	destinationDeployment, err := services.ResolveOne(destinationConfig, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if sourceDeployment.Data[0].RuntimeVolume == destinationDeployment.Data[0].RuntimeVolume {
		t.Fatal("migration fixture did not derive distinct runtime volume names")
	}
	sourceHost := dindHost(sourceConfig, facts.Service{Name: "hello", Project: sourceDeployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	runServiceChanges(t, provider, source, sourceConfig, buildPlan(t, planner.New(provider), sourceHost, sourceConfig))
	assertExec(t, source, dockerVolumeWriteScript(sourceDeployment.Data[0].RuntimeVolume, "BEBOP_M4_PORTABLE_STATE"))
	sourceHost.MachineID = "m4-source"
	sourceHost.Services[0] = facts.Service{Name: "hello", Project: sourceDeployment.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: sourceDeployment.SourceDigest, Runtime: "running", Health: "healthy"}
	repository, err := backup.Open(sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(repository.Root(), func(filename string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(filename, 0o700)
			}
			return nil
		})
	})
	snapshot, err := backup.Create(context.Background(), repository, backup.CreateRequest{HostAlias: "source", Target: "dind-source", Host: sourceHost, Config: sourceConfig, Service: "hello", Transport: source})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Verify(snapshot.Snapshot.SnapshotID); err != nil {
		t.Fatal(err)
	}
	assertExec(t, source, "docker --context default ps --quiet --filter label=com.docker.compose.project="+transport.ShellQuote(sourceDeployment.Project)+" --filter status=running | grep -q .")

	destinationHost := dindHost(destinationConfig, facts.Service{Name: "hello", Project: destinationDeployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	destinationHost.MachineID = "m4-destination"
	restoreRequest := backup.RestoreRequest{SnapshotID: snapshot.Snapshot.SnapshotID, HostAlias: "destination", Target: "dind-destination", Config: destinationConfig, Host: destinationHost, Service: "hello", Transport: destination}
	restorePlan, err := backup.BuildRestorePlan(context.Background(), repository, restoreRequest)
	if err != nil {
		t.Fatal(err)
	}
	if restorePlan.Services[0].Resources[0].Destination != destinationDeployment.Data[0].RuntimeVolume || restorePlan.Services[0].Resources[0].Exists {
		t.Fatalf("restore did not map a missing destination logical resource: %#v", restorePlan)
	}
	if _, err := backup.ApplyRestore(context.Background(), repository, restorePlan, restoreRequest); err != nil {
		t.Fatal(err)
	}
	assertExec(t, destination, dockerVolumeReadScript(destinationDeployment.Data[0].RuntimeVolume, "BEBOP_M4_PORTABLE_STATE"))
	runServiceChanges(t, provider, destination, destinationConfig, buildPlan(t, planner.New(provider), destinationHost, destinationConfig))
	assertExec(t, destination, dockerVolumeReadScript(destinationDeployment.Data[0].RuntimeVolume, "BEBOP_M4_PORTABLE_STATE"))
}

func startDind(t *testing.T) *dockerExecTransport {
	t.Helper()
	command := exec.Command("docker", "run", "--rm", "-d", "--privileged", "docker:27-dind")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Skipf("privileged disposable Docker-in-Docker is unavailable: %v\n%s", err, output)
	}
	container := strings.TrimSpace(string(output))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	transport := &dockerExecTransport{container: container}
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := transport.Run(context.Background(), transportRequest("docker --context default info >/dev/null")); err == nil {
			if _, err := transport.Run(context.Background(), transportRequest("apk add --no-cache coreutils findutils tar >/dev/null")); err != nil {
				t.Skipf("disposable Docker-in-Docker cannot install required GNU test utilities: %v", err)
			}
			if _, err := transport.Run(context.Background(), transportRequest("docker --context default compose version >/dev/null")); err == nil {
				return transport
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Skip("disposable Docker-in-Docker did not become Compose-ready within 45s")
	return nil
}

func transportRequest(script string) transport.Request {
	return transport.Request{Script: script, Privileged: true}
}

func writeComposeFixture(t *testing.T, root, state, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  hello:
    image: busybox:1.36.1
    command: ["sh", "-c", "touch /tmp/ready; sleep 600"]
    labels:
      - "bebop.integration.version=` + version + `"
    healthcheck:
      test: ["CMD-SHELL", "test -f /tmp/ready"]
      interval: 1s
      timeout: 1s
      retries: 3
    volumes:
      - state:/data
volumes:
  state: {}
`
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	contents := `version = 1

[server]
name = "integration"

[storage]
data_root = "/work/bebop"

[services.hello]
type = "compose"
source = "services/hello"
state = "` + state + `"
health_timeout = "30s"
`
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeBackupComposeFixture(t *testing.T, root, server string) {
	t.Helper()
	writeComposeFixture(t, root, "running", "backup")
	filename := filepath.Join(root, "bebop.toml")
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(contents), `name = "integration"`, `name = "`+server+`"`, 1) + `
[backup]
destination = ".bebop/backups"

[[services.hello.data]]
name = "app-data"
type = "volume"
volume = "state"

[services.hello.backup]
consistency = "stop"
`
	if err := os.WriteFile(filename, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

func loadComposeFixture(t *testing.T, root string) config.Config {
	t.Helper()
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func dindHost(cfg config.Config, service facts.Service) facts.HostFacts {
	return facts.HostFacts{Target: "dind", OS: facts.OS{ID: "debian", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "apt", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: cfg.Storage.DataRoot, Exists: true, Mode: "750", UID: 0, GID: 0}, Docker: facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}, Services: []facts.Service{service}}
}

func buildPlan(t *testing.T, builder *planner.Planner, host facts.HostFacts, cfg config.Config) plan.Plan {
	t.Helper()
	result, err := builder.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func runServiceChanges(t *testing.T, provider modules.Compose, target *dockerExecTransport, cfg config.Config, result plan.Plan) {
	t.Helper()
	for _, change := range result.Changes {
		if err := provider.Apply(context.Background(), target, cfg, change); err != nil {
			t.Fatalf("apply %s: %v", change.ID, err)
		}
		if change.Action.Kind == "service.deploy" {
			if actual := targetDeploymentDigest(t, target); actual != change.Action.SourceDigest {
				t.Fatalf("deploy %s activated digest %s, want %s; manifest:\n%s", change.ID, actual, change.Action.SourceDigest, targetDeploymentManifest(t, target))
			}
		}
		if err := provider.Verify(context.Background(), target, cfg, change); err != nil {
			t.Fatalf("verify %s: %v", change.ID, err)
		}
	}
}

func ids(result plan.Plan) string {
	values := make([]string, 0, len(result.Changes))
	for _, change := range result.Changes {
		values = append(values, change.ID)
	}
	return strings.Join(values, ",")
}

func assertExec(t *testing.T, target *dockerExecTransport, script string) {
	t.Helper()
	if _, err := target.Run(context.Background(), transport.Request{Script: script, Privileged: true}); err != nil {
		t.Fatal(err)
	}
}

func targetDeploymentDigest(t *testing.T, target *dockerExecTransport) string {
	t.Helper()
	script := `cd /work/bebop/services/hello/current
find . -type f ! -path './.bebop-secret.env' ! -path './.bebop-secret-fingerprint' -printf '%P\n' | LC_ALL=C sort | while IFS= read -r file; do
  test -n "$file" || continue
  mode=$(stat -c '%a' -- "$file")
  checksum=$(sha256sum -- "$file" | awk '{print $1}')
  printf '%s\t%s\t%s\n' "$mode" "$checksum" "$file"
done | sha256sum | awk '{print $1}'`
	result, err := target.Run(context.Background(), transport.Request{Script: script, Privileged: true})
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(result.Stdout)
}

func targetDeploymentManifest(t *testing.T, target *dockerExecTransport) string {
	t.Helper()
	result, err := target.Run(context.Background(), transport.Request{Script: `cd /work/bebop/services/hello/current
find . -type f ! -path './.bebop-secret.env' ! -path './.bebop-secret-fingerprint' -printf '%P\n' | LC_ALL=C sort | while IFS= read -r file; do
  test -n "$file" || continue
  mode=$(stat -c '%a' -- "$file")
  checksum=$(sha256sum -- "$file" | awk '{print $1}')
  printf '%s\t%s\t%s\n' "$mode" "$checksum" "$file"
done`, Privileged: true})
	if err != nil {
		t.Fatal(err)
	}
	return result.Stdout
}

type dockerExecTransport struct {
	container string
	lock      sync.Mutex
}

func (target *dockerExecTransport) Run(ctx context.Context, request transport.Request) (transport.Result, error) {
	command := exec.CommandContext(ctx, "docker", "exec", "-i", target.container, "sh", "-ceu", request.Script)
	command.Stdin = bytes.NewReader(request.Stdin)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	result := transport.Result{Stdout: stdout.String(), Stderr: strings.TrimSpace(stderr.String())}
	if err == nil {
		return result, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.ExitCode = exit.ExitCode()
		return result, &transport.ExitError{Code: result.ExitCode, Stderr: result.Stderr}
	}
	return result, fmt.Errorf("docker exec: %w", err)
}

func (target *dockerExecTransport) RunStream(ctx context.Context, request transport.StreamRequest, output io.Writer) (transport.Result, error) {
	command := exec.CommandContext(ctx, "docker", "exec", "-i", target.container, "sh", "-ceu", request.Script)
	command.Stdin = request.Stdin
	if output == nil {
		output = io.Discard
	}
	var stderr bytes.Buffer
	command.Stdout, command.Stderr = output, &stderr
	err := command.Run()
	result := transport.Result{Stderr: strings.TrimSpace(stderr.String())}
	if err == nil {
		return result, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		result.ExitCode = exit.ExitCode()
		return result, &transport.ExitError{Code: result.ExitCode, Stderr: result.Stderr}
	}
	return result, fmt.Errorf("docker exec stream: %w", err)
}

func (target *dockerExecTransport) AcquireApplyLock(context.Context) (transport.ApplyLock, error) {
	if !target.lock.TryLock() {
		return nil, &transport.LockError{Busy: true}
	}
	return dockerExecLock{mutex: &target.lock}, nil
}

type dockerExecLock struct{ mutex *sync.Mutex }

func (lock dockerExecLock) Release() error { lock.mutex.Unlock(); return nil }

func (target *dockerExecTransport) ReadFile(ctx context.Context, filename string) (string, error) {
	result, err := target.Run(ctx, transportRequest("cat -- "+shellQuote(filename)))
	return result.Stdout, err
}

func (*dockerExecTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (target *dockerExecTransport) Description() string {
	return "disposable Docker-in-Docker " + target.container
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func dockerVolumeWriteScript(volume, value string) string {
	return "docker --context default run --rm -v " + transport.ShellQuote(volume+":/data") + " busybox:1.36.1 sh -ceu " + transport.ShellQuote("printf %s "+transport.ShellQuote(value)+" > /data/state")
}
func dockerVolumeReadScript(volume, value string) string {
	return "docker --context default run --rm -v " + transport.ShellQuote(volume+":/data:ro") + " busybox:1.36.1 sh -ceu " + transport.ShellQuote("test \"$(cat /data/state)\" = "+transport.ShellQuote(value))
}
