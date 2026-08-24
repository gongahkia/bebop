//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/backup"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/maintenance"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/transport"
)

// TestMaintenanceBackupRetentionAgainstDisposableDind proves the M7 retention
// composition against a real Compose target. It uses the unchanged M4 backup
// path and M7 maintenance provenance/scope: verified job snapshots retain the
// latest two while an otherwise identical manual snapshot remains available.
func TestMaintenanceBackupRetentionAgainstDisposableDind(t *testing.T) {
	if testing.Short() || os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run maintenance integration")
	}
	target := startDind(t)
	root := t.TempDir()
	writeBackupComposeFixture(t, root, "maintenance")
	cfg := loadComposeFixture(t, root)
	cfg.Backup.Destination = filepath.Join(t.TempDir(), "backups")
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	host := dindHost(cfg, facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	runServiceChanges(t, modules.Compose{PollInterval: 50 * time.Millisecond}, target, cfg, buildPlan(t, planner.New(modules.Compose{PollInterval: 50 * time.Millisecond}), host, cfg))
	assertExec(t, target, dockerVolumeWriteScript(deployment.Data[0].RuntimeVolume, "BEBOP_M7_RETAINED_STATE"))
	host.MachineID = "m7-maintenance"
	host.Services[0] = facts.Service{Name: "hello", Project: deployment.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: deployment.SourceDigest, Runtime: "running", Health: "healthy"}
	repository, err := backup.Open(cfg)
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
	manual, err := backup.Create(context.Background(), repository, backup.CreateRequest{HostAlias: "pi", Target: "dind-maintenance", Host: host, Config: cfg, Service: "hello", Transport: target})
	if err != nil {
		t.Fatal(err)
	}
	schedule, err := config.ParseMaintenanceSchedule("daily@03:00")
	if err != nil {
		t.Fatal(err)
	}
	job := config.MaintenanceJob{Name: "nightly-backup", Type: "backup", Target: "pi", Service: "hello", Enabled: true, Schedule: schedule}
	scope := maintenance.MaintenanceScope(job, "dind-maintenance")
	created := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		snapshot, createErr := backup.Create(context.Background(), repository, backup.CreateRequest{HostAlias: "pi", Target: "dind-maintenance", Host: host, Config: cfg, Service: "hello", Transport: target, Maintenance: &backup.MaintenanceProvenance{Job: job.Name, Scope: scope, RunID: "run-" + string(rune('a'+index)) + "-abcdef", JobFingerprint: strings.Repeat("a", 64)}})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, verifyErr := repository.Verify(snapshot.Snapshot.SnapshotID); verifyErr != nil {
			t.Fatal(verifyErr)
		}
		created = append(created, snapshot.Snapshot.SnapshotID)
		assertExec(t, target, "docker --context default ps --quiet --filter label=com.docker.compose.project="+transport.ShellQuote(deployment.Project)+" --filter status=running | grep -q .")
	}
	retention, err := repository.PlanRetention(scope, 2)
	if err != nil || len(retention.Remove) != 1 {
		t.Fatalf("maintenance retention plan = %#v, %v", retention, err)
	}
	if err := repository.ApplyRetention(retention); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Verify(manual.Snapshot.SnapshotID); err != nil {
		t.Fatalf("maintenance retention deleted manual snapshot: %v", err)
	}
	remaining := 0
	for _, id := range created {
		if _, err := repository.Verify(id); err == nil {
			remaining++
		}
	}
	if remaining != 2 {
		t.Fatalf("maintenance retention kept %d job snapshots, want 2", remaining)
	}
}
