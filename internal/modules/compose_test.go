package modules

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestComposePlannerLifecycleAndDeterminism(t *testing.T) {
	cfg := composeFixtureConfig(t, "running", "")
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host := composeHost(cfg, facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	planner := planner.New(Compose{})
	first, err := planner.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := planner.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := first.CanonicalJSON()
	secondJSON, _ := second.CanonicalJSON()
	if string(firstJSON) != string(secondJSON) || first.Fingerprint != second.Fingerprint || changeIDs(first) != "service.hello.deploy,service.hello.start" {
		t.Fatalf("unexpected nondeterministic running plan: %#v / %#v", first, second)
	}
	if first.Changes[0].Action.Script != "" || first.Changes[0].Action.InputFingerprint != deployment.InputFingerprint || first.Changes[1].Risk != plan.NetworkSensitive {
		t.Fatalf("service plan contains incorrect structured semantics: %#v", first.Changes)
	}
	host.Services[0] = facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: deployment.SourceDigest, Runtime: "running", Health: "no-healthcheck"}
	converged, err := planner.Build(host, cfg)
	if err != nil || len(converged.Changes) != 0 {
		t.Fatalf("running service did not converge: %#v %v", converged, err)
	}

	stoppedCfg := composeFixtureConfig(t, "stopped", "")
	stoppedDeployment, err := services.ResolveOne(stoppedCfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	stoppedHost := composeHost(stoppedCfg, facts.Service{Name: "hello", Project: stoppedDeployment.Project, DesiredState: "stopped", DeploymentPresent: true, DeploymentDigest: stoppedDeployment.SourceDigest, Runtime: "running", Health: "no-healthcheck"})
	stopped, err := planner.Build(stoppedHost, stoppedCfg)
	if err != nil || changeIDs(stopped) != "service.hello.stop" {
		t.Fatalf("unexpected stopped plan: %#v %v", stopped, err)
	}

	absentCfg := composeFixtureConfig(t, "absent", "")
	absentDeployment, err := services.ResolveOne(absentCfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	absentHost := composeHost(absentCfg, facts.Service{Name: "hello", Project: absentDeployment.Project, DesiredState: "absent", DeploymentPresent: true, Runtime: "stopped", Health: "stopped"})
	absent, err := planner.Build(absentHost, absentCfg)
	if err != nil || changeIDs(absent) != "service.hello.remove" || strings.Contains(absent.Changes[0].Desired, "delete") {
		t.Fatalf("unexpected absent plan: %#v %v", absent, err)
	}
}

func TestComposeApplyRejectsChangedSourceBeforeTransportMutation(t *testing.T) {
	cfg := composeFixtureConfig(t, "running", "")
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host := composeHost(cfg, facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	result, err := planner.New(Compose{}).Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg.SourceDirectory(), "services", "hello", "compose.yaml"), []byte("services:\n  hello:\n    image: alpine:3.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tr := &serviceRecordingTransport{}
	if err := (Compose{}).Apply(context.Background(), tr, cfg, result.Changes[0]); err == nil || tr.calls != 0 {
		t.Fatalf("source change was not rejected before transport mutation: calls=%d err=%v", tr.calls, err)
	}
}

func TestComposeBlocksExistingStoragePlacementChange(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte("services:\n  hello:\n    image: busybox:1.36.1\n    volumes:\n      - type: bind\n        source: ${BEBOP_STORAGE_BULK}/data\n        target: /data\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	contents := "version = 1\n[storage.resources.bulk]\nmount='/mnt/bulk'\nfilesystem_uuid='11111111-2222-3333-4444-555555555555'\n[services.hello]\ntype='compose'\nsource='services/hello'\n[[services.hello.data]]\nname='data'\ntype='path'\nstorage='bulk'\npath='data'\n"
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host := composeHost(cfg, facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: deployment.SourceDigest, PlacementFingerprint: "old-placement", Runtime: "running", Health: "no-healthcheck"})
	host.Storage = facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/mnt/bulk", UUID: "11111111-2222-3333-4444-555555555555"}}}
	result, err := planner.New(Compose{}).Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Changes) == 0 || result.Changes[0].Blocked == "" || !strings.Contains(result.Changes[0].Blocked, "backup/restore") {
		t.Fatalf("placement change was not blocked for migration: %#v", result.Changes)
	}
}

func TestStoragePathSafetyRejectsAncestorSymlink(t *testing.T) {
	mount := t.TempDir()
	external := t.TempDir()
	if err := os.Symlink(external, filepath.Join(mount, "redirect")); err != nil {
		t.Fatal(err)
	}
	targetPath := filepath.Join(mount, "redirect", "service")
	if err := exec.Command("sh", "-c", storagePathSafetyScript(mount, targetPath)).Run(); err == nil {
		t.Fatal("storage path safety accepted a symlink ancestor")
	}
	if _, err := os.Stat(filepath.Join(external, "service")); !os.IsNotExist(err) {
		t.Fatalf("storage path safety wrote through a symlink: %v", err)
	}
}

func TestComposeScriptsPreserveVolumesAndDoNotLeakSecret(t *testing.T) {
	cfg := composeFixtureConfig(t, "running", "TOKEN=BEBOP_TEST_SECRET_DO_NOT_LEAK\n")
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	deploy := deployScript(cfg.Storage.DataRoot, deployment)
	remove := removeScript(cfg.Storage.DataRoot, deployment)
	if strings.Contains(deploy, "BEBOP_TEST_SECRET_DO_NOT_LEAK") || strings.Contains(remove, "-v") || strings.Contains(remove, "rm -rf") {
		t.Fatalf("service scripts crossed a secret or persistent-data boundary:\n%s\n%s", deploy, remove)
	}
	if !strings.Contains(deploy, "config -q") || !strings.Contains(deploy, "mv -Tf") || !strings.Contains(remove, "down --remove-orphans") {
		t.Fatalf("service scripts do not stage/validate/activate safely:\n%s\n%s", deploy, remove)
	}
}

func TestComposeServiceProjectsAreIsolated(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"alpha", "beta"} {
		if err := os.MkdirAll(filepath.Join(root, "services", name), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "services", name, "compose.yaml"), []byte("services:\n  "+name+":\n    image: alpine:3.20\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	contents := `version = 1

[server]
name = "isolation"

[services.alpha]
type = "compose"
source = "services/alpha"

[services.beta]
type = "compose"
source = "services/beta"
`
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	before, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	initial, err := services.ResolveAll(before)
	if err != nil {
		t.Fatal(err)
	}
	if initial[0].Project == initial[1].Project {
		t.Fatalf("services received the same Compose project: %#v", initial)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "alpha", "compose.yaml"), []byte("services:\n  alpha:\n    image: alpine:3.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	host := composeHost(after,
		facts.Service{Name: "alpha", Project: initial[0].Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: initial[0].SourceDigest, Runtime: "running", Health: "no-healthcheck"},
	)
	host.Services = append(host.Services, facts.Service{Name: "beta", Project: initial[1].Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: initial[1].SourceDigest, Runtime: "running", Health: "no-healthcheck"})
	result, err := planner.New(Compose{}).Build(host, after)
	if err != nil || changeIDs(result) != "service.alpha.update,service.alpha.start" {
		t.Fatalf("alpha update touched another project: %#v %v", result.Changes, err)
	}
}

func TestAggregateComposeRuntimeDistinguishesHealth(t *testing.T) {
	healthy := &struct {
		Status string `json:"Status"`
	}{Status: "healthy"}
	starting := &struct {
		Status string `json:"Status"`
	}{Status: "starting"}
	for _, test := range []struct {
		name   string
		state  []composeContainerState
		want   string
		health string
	}{
		{"no healthcheck", []composeContainerState{{Running: true, Status: "running"}}, "running", "no-healthcheck"},
		{"healthy", []composeContainerState{{Running: true, Status: "running", Health: healthy}}, "running", "healthy"},
		{"starting", []composeContainerState{{Running: true, Status: "running", Health: starting}}, "starting", "starting"},
		{"stopped", []composeContainerState{{Status: "exited"}}, "stopped", "stopped"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime, health, _ := aggregateComposeRuntime(test.state)
			if runtime != test.want || health != test.health {
				t.Fatalf("got %s/%s, want %s/%s", runtime, health, test.want, test.health)
			}
		})
	}
}

func composeFixtureConfig(t *testing.T, state, secret string) config.Config {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  hello:
    image: alpine:3.20
    command: ["sleep", "infinity"]
    ports: ["127.0.0.1:8081:80"]
`
	secretDeclaration := ""
	if secret != "" {
		compose += "    env_file: .bebop-secret.env\n"
		if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "secrets", "hello.env"), []byte(secret), 0o600); err != nil {
			t.Fatal(err)
		}
		secretDeclaration = "secret_env_file = \"secrets/hello.env\"\n"
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	contents := "version = 1\n\n[server]\nname = \"home\"\n\n[services.hello]\ntype = \"compose\"\nsource = \"services/hello\"\nstate = \"" + state + "\"\n" + secretDeclaration
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func composeHost(cfg config.Config, service facts.Service) facts.HostFacts {
	return facts.HostFacts{Target: "local", OS: facts.OS{ID: "debian", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "apt", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: cfg.Storage.DataRoot, Exists: true, Mode: "750", UID: 0, GID: 0}, Docker: facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}, Services: []facts.Service{service}}
}

func changeIDs(result plan.Plan) string {
	ids := make([]string, 0, len(result.Changes))
	for _, change := range result.Changes {
		ids = append(ids, change.ID)
	}
	return strings.Join(ids, ",")
}

type serviceRecordingTransport struct{ calls int }

func (recording *serviceRecordingTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	recording.calls++
	return transport.Result{}, nil
}
func (*serviceRecordingTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (*serviceRecordingTransport) FileExists(context.Context, string) (bool, error) {
	return false, nil
}
func (*serviceRecordingTransport) Description() string { return "recording" }
