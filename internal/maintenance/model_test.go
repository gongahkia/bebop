package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/notification"
)

type recordingExecutor struct {
	mu      sync.Mutex
	calls   int
	outcome Outcome
	err     error
}

type failingNotifier struct{}

func (failingNotifier) Process(context.Context, []notification.Event) ([]notification.DeliveryResult, error) {
	return nil, errors.New("BEBOP_TEST_SECRET_DO_NOT_LEAK")
}

func (executor *recordingExecutor) Execute(context.Context, config.MaintenanceJob, Invocation) (Outcome, error) {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	executor.calls++
	return executor.outcome, executor.err
}

func (executor *recordingExecutor) count() int {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.calls
}

func TestEligibleAtUsesInclusiveStartExclusiveEndAndCrossMidnight(t *testing.T) {
	location := time.Local
	job := config.MaintenanceJob{Window: &config.MaintenanceWindow{Start: "02:00", End: "05:00"}}
	for _, test := range []struct {
		clock time.Time
		want  bool
	}{
		{time.Date(2026, 8, 24, 2, 0, 0, 0, location), true},
		{time.Date(2026, 8, 24, 4, 59, 59, 0, location), true},
		{time.Date(2026, 8, 24, 5, 0, 0, 0, location), false},
		{time.Date(2026, 8, 24, 1, 59, 59, 0, location), false},
	} {
		if got := EligibleAt(job, test.clock); got != test.want {
			t.Fatalf("EligibleAt(%s) = %t, want %t", test.clock, got, test.want)
		}
	}
	job.Window = &config.MaintenanceWindow{Start: "23:00", End: "03:00"}
	for _, test := range []struct {
		hour int
		want bool
	}{{22, false}, {23, true}, {0, true}, {2, true}, {3, false}} {
		clock := time.Date(2026, 8, 24, test.hour, 0, 0, 0, location)
		if got := EligibleAt(job, clock); got != test.want {
			t.Fatalf("cross-midnight EligibleAt(%s) = %t, want %t", clock, got, test.want)
		}
	}
}

func TestRunnerRecordsSuccessFailureAndPolicySkips(t *testing.T) {
	clock := time.Date(2026, 8, 24, 3, 0, 0, 0, time.Local)
	base := maintenanceConfig(t)
	history, err := NewHistory(base)
	if err != nil {
		t.Fatal(err)
	}
	job := testJob()
	executor := &recordingExecutor{outcome: Outcome{Result: Success, Details: Details{SnapshotID: "20260824T030000Z-0123456789ab"}}}
	runner := Runner{Jobs: []config.MaintenanceJob{job}, Clock: func() time.Time { return clock }, History: history, Locks: LocalLocker{Directory: filepath.Join(base.SourceDirectory(), ".bebop", "maintenance", "locks")}, Executor: executor}
	record, err := runner.Run(context.Background(), job.Name, RunOptions{})
	if err != nil || record.Result != Success || executor.count() != 1 {
		t.Fatalf("successful run = %#v, %v, calls=%d", record, err, executor.count())
	}
	if records, err := history.List(job.Name); err != nil || len(records) != 1 || records[0].RunID != record.RunID {
		t.Fatalf("successful run was not recorded: %#v %v", records, err)
	}

	job.Window = &config.MaintenanceWindow{Start: "04:00", End: "05:00"}
	runner.Jobs = []config.MaintenanceJob{job}
	record, err = runner.Run(context.Background(), job.Name, RunOptions{})
	if err != nil || record.Result != Skipped || record.Details.Reason != "outside-window" || executor.count() != 1 {
		t.Fatalf("window skip = %#v, %v, calls=%d", record, err, executor.count())
	}
	record, err = runner.Run(context.Background(), job.Name, RunOptions{IgnoreWindow: true})
	if err != nil || record.Result != Success || executor.count() != 2 {
		t.Fatalf("manual window override = %#v, %v, calls=%d", record, err, executor.count())
	}
	if _, err := runner.Run(context.Background(), job.Name, RunOptions{Origin: "scheduled", IgnoreWindow: true}); err == nil {
		t.Fatal("scheduled run bypassed maintenance window")
	}

	executor.err = errors.New("target unavailable")
	record, err = runner.Run(context.Background(), job.Name, RunOptions{IgnoreWindow: true})
	if err == nil || record.Result != Failure || record.Error != "operation failed; inspect command output or scheduler journal" {
		t.Fatalf("failed run = %#v, %v", record, err)
	}
	executor.err = errors.New("BEBOP_M7_SECRET_DO_NOT_RENDER")
	record, err = runner.Run(context.Background(), job.Name, RunOptions{IgnoreWindow: true})
	if err == nil || strings.Contains(record.Error, "BEBOP_M7_SECRET_DO_NOT_RENDER") {
		t.Fatalf("history error leaked arbitrary operation text: %#v, %v", record, err)
	}
}

func TestHistoryConcurrentWritesRemainBoundedAndSecretFree(t *testing.T) {
	base := maintenanceConfig(t)
	base.Maintenance.HistoryMaxEntries = 5
	history, err := NewHistory(base)
	if err != nil {
		t.Fatal(err)
	}
	const sentinel = "BEBOP_M7_SECRET_DO_NOT_RENDER"
	var group sync.WaitGroup
	for index := 0; index < 12; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			record := Record{SchemaVersion: HistorySchemaVersion, RunID: "run-100" + string(rune('a'+index)) + "-abcdef", Job: "nightly-backup", JobFingerprint: strings.Repeat("a", 64), Operation: "backup", Target: "pi", Origin: "scheduled", StartedAt: time.Unix(int64(index), 0).UTC(), FinishedAt: time.Unix(int64(index+1), 0).UTC(), Result: Success}
			if err := history.Append(record); err != nil {
				t.Errorf("append: %v", err)
			}
		}(index)
	}
	group.Wait()
	records, err := history.List("")
	if err != nil || len(records) != 5 {
		t.Fatalf("bounded concurrent history = %d records, %v", len(records), err)
	}
	for _, record := range records {
		if strings.Contains(record.Error, sentinel) || strings.Contains(record.Details.Reason, sentinel) {
			t.Fatalf("history record leaked secret sentinel: %#v", record)
		}
	}
}

func TestLocalJobLockIsCrashSafeProcessLease(t *testing.T) {
	directory := t.TempDir()
	first, err := (LocalLocker{Directory: directory}).Acquire("nightly-backup")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (LocalLocker{Directory: directory}).Acquire("nightly-backup"); err == nil {
		t.Fatal("same job acquired a second local lease")
	}
	if independent, err := (LocalLocker{Directory: directory}).Acquire("weekly-doctor"); err != nil {
		t.Fatalf("independent job was over-serialized: %v", err)
	} else if err := independent.Release(); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if second, err := (LocalLocker{Directory: directory}).Acquire("nightly-backup"); err != nil {
		t.Fatalf("released lease remained stale: %v", err)
	} else if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestHistoryRejectsWorldWritableDirectory(t *testing.T) {
	base := maintenanceConfig(t)
	root, err := HistoryRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := NewHistory(base); err == nil || !strings.Contains(err.Error(), "world-writable") {
		t.Fatalf("world-writable history directory was accepted: %v", err)
	}
}

func TestNotificationFailureDoesNotChangeMaintenanceOperationResult(t *testing.T) {
	base := maintenanceConfig(t)
	history, err := NewHistory(base)
	if err != nil {
		t.Fatal(err)
	}
	job := testJob()
	runner := Runner{Jobs: []config.MaintenanceJob{job}, Clock: func() time.Time { return time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC) }, History: history, Locks: LocalLocker{Directory: filepath.Join(base.SourceDirectory(), ".bebop", "maintenance", "locks")}, Executor: &recordingExecutor{outcome: Outcome{Result: Success}}, Notifier: failingNotifier{}}
	result, err := runner.RunDetailed(context.Background(), job.Name, RunOptions{Origin: "scheduled"})
	if err != nil || result.Record.Result != Success || result.NotificationError == "" || strings.Contains(result.NotificationError, "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
		t.Fatalf("notification failure changed or leaked maintenance operation: %#v %v", result, err)
	}
	records, err := history.List(job.Name)
	if err != nil || len(records) != 1 || records[0].Result != Success {
		t.Fatalf("notification failure changed operation history: %#v %v", records, err)
	}
}

func maintenanceConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg = config.WithSourceDirectory(cfg, t.TempDir())
	cfg.Maintenance = &config.Maintenance{Version: config.MaintenanceSchemaVersion, HistoryDirectory: ".bebop/history", HistoryMaxEntries: 100}
	return cfg
}

func testJob() config.MaintenanceJob {
	schedule, _ := config.ParseMaintenanceSchedule("daily@03:00")
	return config.MaintenanceJob{Name: "nightly-backup", Type: "backup", Target: "pi", Service: "hello", Enabled: true, Schedule: schedule}
}
