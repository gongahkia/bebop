package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
)

func TestSystemdUnitsAreDeterministicAndShellFree(t *testing.T) {
	scheduler := testSystemd(t)
	jobs := []config.MaintenanceJob{testScheduledJob(t)}
	first, err := scheduler.DesiredUnits(jobs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := scheduler.DesiredUnits(jobs)
	if err != nil {
		t.Fatal(err)
	}
	service := first[scheduler.ServiceName("nightly-backup")]
	if service != second[scheduler.ServiceName("nightly-backup")] || UnitFingerprint(service) != UnitFingerprint(second[scheduler.ServiceName("nightly-backup")]) {
		t.Fatal("systemd unit generation was nondeterministic")
	}
	if strings.Contains(service, "/bin/sh -c") || !strings.Contains(service, "ExecStart=") || !strings.Contains(service, "\"maintenance\" \"run\"") {
		t.Fatalf("generated service is not a direct typed invocation: %s", service)
	}
	if !strings.Contains(service, "project %% path") || !strings.Contains(service, "bebop %% binary") {
		t.Fatalf("systemd specifier escaping missing: %s", service)
	}
	timer := first[scheduler.TimerName("nightly-backup")]
	if !strings.Contains(timer, "OnCalendar=*-*-* 03:00:00") || !strings.Contains(timer, "Persistent=true") {
		t.Fatalf("unexpected timer: %s", timer)
	}
	for _, malicious := range []config.MaintenanceJob{
		{Name: "bad\nname", Enabled: true},
		{Name: "-leading", Enabled: true},
		{Name: "okay", Enabled: true, Schedule: config.MaintenanceSchedule{Kind: "daily", At: "03:00\nInjected=true"}},
	} {
		if _, err := scheduler.DesiredUnits([]config.MaintenanceJob{malicious}); err == nil {
			t.Fatalf("unsafe scheduler input accepted: %#v", malicious)
		}
	}
}

func TestSystemdStatusDetectsTamperingAndConfigDrift(t *testing.T) {
	scheduler := testSystemd(t)
	job := testScheduledJob(t)
	units, err := scheduler.DesiredUnits([]config.MaintenanceJob{job})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range units {
		if err := os.WriteFile(filepath.Join(scheduler.UnitDirectory, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	statuses, err := scheduler.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || len(statuses) != 1 || statuses[0].State != "current" {
		t.Fatalf("current status = %#v, %v", statuses, err)
	}
	service := filepath.Join(scheduler.UnitDirectory, scheduler.ServiceName(job.Name))
	if err := os.WriteFile(service, []byte("manual edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	statuses, err = scheduler.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("tampered status = %#v, %v", statuses, err)
	}
	if err := os.WriteFile(service, []byte(units[scheduler.ServiceName(job.Name)]), 0o644); err != nil {
		t.Fatal(err)
	}
	changed := job
	changed.Schedule, _ = config.ParseMaintenanceSchedule("daily@04:00")
	statuses, err = scheduler.Status(context.Background(), []config.MaintenanceJob{changed})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("schedule drift status = %#v, %v", statuses, err)
	}
	changed = job
	changedScheduler := scheduler
	changedScheduler.Executable = "/opt/new bebop"
	statuses, err = changedScheduler.Status(context.Background(), []config.MaintenanceJob{changed})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("binary drift status = %#v, %v", statuses, err)
	}
	changed = job
	changed.Target = "nuc"
	statuses, err = scheduler.Status(context.Background(), []config.MaintenanceJob{changed})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("job policy drift status = %#v, %v", statuses, err)
	}
}

func TestSystemdInstallReconcilesOnlyOwnedUnits(t *testing.T) {
	scheduler := testSystemd(t)
	job := testScheduledJob(t)
	if err := os.WriteFile(filepath.Join(scheduler.UnitDirectory, "unrelated.service"), []byte("[Service]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	changes, err := scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false)
	if err != nil || len(changes) != 2 {
		t.Fatalf("install = %#v, %v", changes, err)
	}
	changes, err = scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false)
	if err != nil || len(changes) != 0 {
		t.Fatalf("second install was not idempotent: %#v, %v", changes, err)
	}
	if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, "unrelated.service")); err != nil {
		t.Fatalf("unrelated unit was touched: %v", err)
	}
	changes, err = scheduler.Install(context.Background(), nil, false)
	if err != nil || len(changes) != 2 {
		t.Fatalf("removed-job reconciliation = %#v, %v", changes, err)
	}
	if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, scheduler.ServiceName(job.Name))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete Bebop unit remained: %v", err)
	}
	if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, "unrelated.service")); err != nil {
		t.Fatalf("reconcile deleted unrelated unit: %v", err)
	}

	if _, err := scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false); err != nil {
		t.Fatal(err)
	}
	changes, err = scheduler.Uninstall(context.Background(), []config.MaintenanceJob{job})
	if err != nil || len(changes) != 2 {
		t.Fatalf("uninstall = %#v, %v", changes, err)
	}
	if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, "unrelated.service")); err != nil {
		t.Fatalf("uninstall deleted unrelated unit: %v", err)
	}
}

func TestSystemdMigratesOnlyMatchingLegacyM7Units(t *testing.T) {
	scheduler := testSystemd(t)
	job := testScheduledJob(t)
	service, err := scheduler.renderService(job, scheduler.legacyServiceName(job.Name))
	if err != nil {
		t.Fatal(err)
	}
	timer, err := scheduler.renderTimer(job, scheduler.legacyServiceName(job.Name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scheduler.UnitDirectory, scheduler.legacyServiceName(job.Name)), []byte(service), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scheduler.UnitDirectory, scheduler.legacyTimerName(job.Name)), []byte(timer), 0o644); err != nil {
		t.Fatal(err)
	}
	statuses, err := scheduler.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || len(statuses) != 1 || statuses[0].State != "stale" || !strings.Contains(statuses[0].Detail, "legacy M7") {
		t.Fatalf("legacy status = %#v, %v", statuses, err)
	}
	changes, err := scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false)
	if err != nil || len(changes) != 4 {
		t.Fatalf("legacy migration = %#v, %v", changes, err)
	}
	for _, filename := range []string{scheduler.legacyServiceName(job.Name), scheduler.legacyTimerName(job.Name)} {
		if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, filename)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy unit survived migration: %s: %v", filename, err)
		}
	}
	if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, scheduler.ServiceName(job.Name))); err != nil {
		t.Fatalf("project-scoped service missing: %v", err)
	}

	other := scheduler
	other.ProjectRoot = filepath.Join(t.TempDir(), "other-project")
	other.ProjectID = SchedulerProjectID(other.ProjectRoot)
	other.ConfigPath = filepath.Join(other.ProjectRoot, "bebop.toml")
	otherService, err := other.renderService(job, other.legacyServiceName(job.Name))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(scheduler.UnitDirectory, scheduler.legacyServiceName(job.Name)), []byte(otherService), 0o644); err != nil {
		t.Fatal(err)
	}
	changes, err = scheduler.Install(context.Background(), []config.MaintenanceJob{job}, true)
	if err != nil || len(changes) != 0 {
		t.Fatalf("foreign legacy unit was claimed: %#v, %v", changes, err)
	}
	if _, err := os.Stat(filepath.Join(scheduler.UnitDirectory, scheduler.legacyServiceName(job.Name))); err != nil {
		t.Fatalf("foreign legacy unit was changed: %v", err)
	}
}

func TestSystemdProjectScopedArtifactsCoexist(t *testing.T) {
	first := testSystemd(t)
	second := first
	second.ProjectRoot = filepath.Join(t.TempDir(), "second-project")
	second.ProjectID = SchedulerProjectID(second.ProjectRoot)
	second.ConfigPath = filepath.Join(second.ProjectRoot, "bebop.toml")
	job := testScheduledJob(t)
	if _, err := first.Install(context.Background(), []config.MaintenanceJob{job}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Install(context.Background(), []config.MaintenanceJob{job}, false); err != nil {
		t.Fatal(err)
	}
	if first.TimerName(job.Name) == second.TimerName(job.Name) {
		t.Fatal("separate projects received the same systemd timer identity")
	}
	if _, err := first.Install(context.Background(), nil, false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(first.UnitDirectory, second.TimerName(job.Name))); err != nil {
		t.Fatalf("first project reconciliation removed second project's timer: %v", err)
	}
}

func TestSystemdCapabilityExplainsUnavailableUserManager(t *testing.T) {
	scheduler := testSystemd(t)
	scheduler.run = func(context.Context, string, ...string) (string, error) {
		return "", errors.New("failed to connect to bus")
	}
	capability, detail := scheduler.Capability(context.Background())
	if capability != SchedulerUnavailable || !strings.Contains(detail, "user manager") {
		t.Fatalf("capability = %s %q", capability, detail)
	}
	scheduler.Platform = "darwin"
	capability, _ = scheduler.Capability(context.Background())
	if capability != SchedulerUnsupported {
		t.Fatalf("non-Linux scheduler capability = %s", capability)
	}
}

func testSystemd(t *testing.T) SystemdUser {
	t.Helper()
	directory := t.TempDir()
	project := filepath.Join(directory, "project % path")
	scheduler := SystemdUser{UnitDirectory: directory, ProjectRoot: project, ProjectID: SchedulerProjectID(project), ConfigPath: filepath.Join(project, "bebop.toml"), InventoryPath: filepath.Join(directory, "inventory path", "hosts.toml"), Executable: filepath.Join(directory, "bebop % binary"), Platform: "linux", Systemctl: "fake-systemctl"}
	scheduler.run = func(_ context.Context, _ string, arguments ...string) (string, error) {
		for _, argument := range arguments {
			if argument == "is-enabled" {
				return "enabled", nil
			}
		}
		return "", nil
	}
	return scheduler
}

func testScheduledJob(t *testing.T) config.MaintenanceJob {
	t.Helper()
	schedule, err := config.ParseMaintenanceSchedule("daily@03:00")
	if err != nil {
		t.Fatal(err)
	}
	return config.MaintenanceJob{Name: "nightly-backup", Type: "backup", Target: "pi", Service: "hello", Enabled: true, Schedule: schedule}
}
