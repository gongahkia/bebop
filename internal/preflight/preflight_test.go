package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestFromFactsSeparatesReadinessFailuresFromOperationalWarnings(t *testing.T) {
	host := facts.HostFacts{
		Target:            "ssh://pi@home",
		OS:                facts.OS{ID: "debian", Name: "Debian", VersionID: "12", Supported: true},
		Architecture:      "arm64",
		ArchitectureKnown: true,
		PackageManager:    "apt",
		Systemd:           true,
		SudoAvailable:     true,
		DataRoot:          facts.Directory{Path: "/srv/bebop"},
	}
	result := FromFacts(target.Target{Kind: target.SSH, User: "pi", Host: "home"}, host)
	if !result.Ready || !result.Reachable || !result.Authenticated {
		t.Fatalf("supported host should be ready: %#v", result)
	}
	if len(result.Checks) == 0 || result.Checks[len(result.Checks)-1].Status != Warn {
		t.Fatalf("expected non-blocking operational warnings: %#v", result.Checks)
	}
	host.PackageManager = "unknown"
	blocked := FromFacts(target.Target{Kind: target.Local}, host)
	if blocked.Ready || blocked.FailureError() == nil {
		t.Fatalf("missing apt should block readiness: %#v", blocked)
	}
}

func TestBackupChecksDescribeControllerRepositoryWithoutMutatingIt(t *testing.T) {
	root := t.TempDir()
	cfg := config.WithSourceDirectory(config.Defaults(), root)
	cfg.Services = []config.Service{{Name: "hello", Type: "compose", Source: "services/hello", Data: []config.DataResource{{Name: "state", Type: "volume", Volume: "data"}}}}
	result := Result{}
	appendBackupChecks(&result, cfg)
	if len(result.Checks) != 2 || result.Checks[1].Code != "backup.destination_absent" {
		t.Fatalf("missing backup destination should be a non-mutating warning: %#v", result.Checks)
	}
	if _, err := os.Stat(filepath.Join(root, cfg.Backup.Destination)); !os.IsNotExist(err) {
		t.Fatalf("doctor unexpectedly created backup repository: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, cfg.Backup.Destination), 0o700); err != nil {
		t.Fatal(err)
	}
	result = Result{}
	appendBackupChecks(&result, cfg)
	if result.Checks[len(result.Checks)-1].Code != "backup.destination_ready" {
		t.Fatalf("existing backup destination was not reported ready: %#v", result.Checks)
	}
}

func TestFailureClassificationProducesActionableResult(t *testing.T) {
	result := unavailable(Result{Target: "ssh://pi@home"}, transport.ClassifyFailure(errors.New("Host key verification failed")), "SSH host-key verification failed")
	if result.Ready || result.Failure != transport.FailureHostKey || result.FailureError() == nil {
		t.Fatalf("unexpected unavailable result: %#v", result)
	}
}
