package backup

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetentionSelectsOnlyVerifiedSnapshotsFromSameMaintenanceScope(t *testing.T) {
	repository := testRepository(t)
	const scope = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	created := make([]Manifest, 0, 5)
	for index := 0; index < 5; index++ {
		created = append(created, retentionSnapshot(t, repository, scope, time.Date(2026, 8, index+1, 3, 0, 0, 0, time.UTC), "nightly-backup"))
	}
	manual := retentionSnapshot(t, repository, "", time.Date(2026, 8, 10, 3, 0, 0, 0, time.UTC), "")
	other := retentionSnapshot(t, repository, strings.Repeat("b", 64), time.Date(2026, 8, 11, 3, 0, 0, 0, time.UTC), "other-backup")
	plan, err := repository.PlanRetention(scope, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Remove) != 2 || plan.Remove[0].SnapshotID != created[0].SnapshotID || plan.Remove[1].SnapshotID != created[1].SnapshotID {
		t.Fatalf("retention selection = %#v", plan)
	}
	if err := repository.ApplyRetention(plan); err != nil {
		t.Fatal(err)
	}
	for _, snapshot := range []Manifest{created[0], created[1]} {
		if _, err := repository.Load(snapshot.SnapshotID); err == nil {
			t.Fatalf("retention did not delete selected snapshot %s", snapshot.SnapshotID)
		}
	}
	for _, snapshot := range append(created[2:], manual, other) {
		if _, err := repository.Verify(snapshot.SnapshotID); err != nil {
			t.Fatalf("retention deleted or corrupted protected snapshot %s: %v", snapshot.SnapshotID, err)
		}
	}
}

func TestRetentionPreservesCorruptKnownSnapshot(t *testing.T) {
	repository := testRepository(t)
	const scope = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	corrupt := retentionSnapshot(t, repository, scope, time.Date(2026, 8, 1, 3, 0, 0, 0, time.UTC), "nightly-backup")
	_ = retentionSnapshot(t, repository, scope, time.Date(2026, 8, 2, 3, 0, 0, 0, time.UTC), "nightly-backup")
	archive := filepath.Join(repository.Root(), snapshotsDirectory, corrupt.SnapshotID, "services", "hello", "data", "app-data.tar")
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	plan, err := repository.PlanRetention(scope, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.CorruptSkipped) != 1 || plan.CorruptSkipped[0] != corrupt.SnapshotID {
		t.Fatalf("corrupt snapshot was not preserved/reported: %#v", plan)
	}
	if len(plan.Remove) != 0 {
		t.Fatalf("retention selected another snapshot while corrupt scope state exists: %#v", plan)
	}
	if _, err := repository.Load(corrupt.SnapshotID); err != nil {
		t.Fatalf("corrupt snapshot was unexpectedly deleted: %v", err)
	}
}

func retentionSnapshot(t *testing.T, repository Repository, scope string, createdAt time.Time, job string) Manifest {
	t.Helper()
	stage, err := repository.Begin(Source{Target: "local"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	stage.manifest.CreatedAt = createdAt
	if scope != "" {
		if err := stage.SetMaintenance(&MaintenanceProvenance{Job: job, Scope: scope, RunID: "run-1-abcdef", JobFingerprint: strings.Repeat("c", 64)}); err != nil {
			t.Fatal(err)
		}
	}
	resource, err := stage.WriteArchive(context.Background(), "services/hello/data/app-data.tar", fixtureArchive(t, map[string]string{"state": "portable"}))
	if err != nil {
		t.Fatal(err)
	}
	resource.Name, resource.Type = "app-data", "volume"
	if err := stage.AddService(ServiceManifest{Name: "hello", ConfigurationDigest: strings.Repeat("d", 64), Consistency: "stop", Resources: []ResourceManifest{resource}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := stage.Complete()
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}
