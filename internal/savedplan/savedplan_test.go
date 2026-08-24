package savedplan

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/artifact"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/target"
)

func fixture(t *testing.T) (artifact.Artifact, facts.HostFacts, config.Config, *planner.Planner) {
	t.Helper()
	current, err := target.Parse("ssh://pi@home")
	if err != nil {
		t.Fatal(err)
	}
	host := facts.HostFacts{
		Target: current.String(), Hostname: "pi", MachineID: "machine-a",
		OS:           facts.OS{ID: "debian", Name: "Debian", VersionID: "12", VersionCodename: "bookworm", Family: "debian", Supported: true},
		Architecture: "arm64", ArchitectureKnown: true, PackageManager: "apt", Systemd: true, SudoAvailable: true,
		EffectiveUser: "pi", SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, DropInSupported: true, AuthorizedKeysPresent: true},
		DataRoot: facts.Directory{Path: config.DefaultDataRoot},
	}
	desired := config.Defaults()
	planner := planner.New(modules.Default()...)
	result, err := planner.Build(host, desired)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := artifact.New("pi", "/work/hosts/pi.toml", current, desired, host, result)
	if err != nil {
		t.Fatal(err)
	}
	return saved, host, desired, planner
}

func TestValidateObservedAcceptsUnchangedAndVolatileState(t *testing.T) {
	saved, host, desired, planner := fixture(t)
	host.MemoryKiB = 999
	host.Kernel = "new-kernel"
	fresh, err := ValidateObserved(saved, desired, host, planner)
	if err != nil || fresh.Fingerprint != saved.Plan.Fingerprint {
		t.Fatalf("unchanged convergence state rejected: %#v %v", fresh, err)
	}
}

func TestValidateObservedRejectsRelevantDriftConfigAndWrongHost(t *testing.T) {
	saved, host, desired, planner := fixture(t)
	host.Docker.Installed = true
	if _, err := ValidateObserved(saved, desired, host, planner); !hasCode(err, errs.PlanStale) {
		t.Fatalf("expected stale Docker state, got %v", err)
	}
	saved, host, desired, planner = fixture(t)
	changedConfig := desired
	changedConfig.Features.Docker = false
	if _, err := ValidateObserved(saved, changedConfig, host, planner); !hasCode(err, errs.PlanStale) {
		t.Fatalf("expected stale configuration, got %v", err)
	}
	saved, host, desired, planner = fixture(t)
	host.MachineID = "machine-b"
	if _, err := ValidateObserved(saved, desired, host, planner); !hasCode(err, errs.TargetIdentityMismatch) {
		t.Fatalf("expected wrong-host rejection, got %v", err)
	}
}

func TestValidateObservedNeverTreatsSelfHashedArtifactScriptsAsAuthority(t *testing.T) {
	saved, host, desired, planner := fixture(t)
	saved.Plan.Changes[0].Action.Script = "arbitrary command"
	if err := saved.Plan.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := saved.Finalize(); err != nil {
		t.Fatal(err)
	}
	if err := saved.Verify(); err != nil {
		t.Fatalf("self-consistent artifact should pass structural verification: %v", err)
	}
	if _, err := ValidateObserved(saved, desired, host, planner); !hasCode(err, errs.PlanStale) {
		t.Fatalf("regenerated plan did not reject altered action semantics: %v", err)
	}
}

func TestValidateConfigRejectsChangedServiceSourceAndSecretWithoutLeakage(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte("services:\n  hello:\n    image: alpine:3.20\n    env_file: .bebop-secret.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const sentinel = "BEBOP_TEST_SECRET_DO_NOT_LEAK"
	if err := os.WriteFile(filepath.Join(root, "secrets", "hello.env"), []byte("TOKEN="+sentinel+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(`version = 1

[server]
name = "home"

[features]
automatic_updates = false
ssh_hardening = false
docker = true
tailscale = false

[services.hello]
type = "compose"
source = "services/hello"
secret_env_file = "secrets/hello.env"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	desired, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := target.Parse("ssh://pi@home")
	if err != nil {
		t.Fatal(err)
	}
	host := facts.HostFacts{Target: current.String(), Hostname: "pi", MachineID: "machine-a", OS: facts.OS{ID: "debian", VersionID: "12", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "apt", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: desired.Storage.DataRoot, Exists: true, Mode: "750", UID: 0, GID: 0}, Docker: facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}, Services: []facts.Service{{Name: "hello", Project: "bebop-home-hello-7e75664d57", DesiredState: "running", Runtime: "missing", Health: "missing"}}}
	planner := planner.New(modules.Default()...)
	result, err := planner.Build(host, desired)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := artifact.New("pi", filepath.Join(root, "bebop.toml"), current, desired, host, result)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(saved)
	if err != nil || strings.Contains(string(encoded), sentinel) {
		t.Fatalf("saved plan leaked a secret: %v %s", err, encoded)
	}
	if err := ValidateConfig(saved, desired); err != nil {
		t.Fatalf("unchanged service input rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte("services:\n  hello:\n    image: alpine:3.21\n    env_file: .bebop-secret.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(saved, desired); !hasCode(err, errs.PlanStale) {
		t.Fatalf("changed service source was not stale: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte("services:\n  hello:\n    image: alpine:3.20\n    env_file: .bebop-secret.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, err := artifact.New("pi", filepath.Join(root, "bebop.toml"), current, desired, host, result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secrets", "hello.env"), []byte("TOKEN=rotated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(fresh, desired); !hasCode(err, errs.PlanStale) {
		t.Fatalf("rotated secret was not stale: %v", err)
	}
}

func hasCode(err error, code errs.Code) bool {
	var categorized *errs.Error
	return errors.As(err, &categorized) && categorized.Code == code
}
