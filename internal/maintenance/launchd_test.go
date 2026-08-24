package maintenance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
)

func TestLaunchdPlistsAreDeterministicEscapedAndDirect(t *testing.T) {
	scheduler, _ := testLaunchd(t)
	scheduler.ProjectRoot = filepath.Join(t.TempDir(), "project & <space>")
	scheduler.ConfigPath = filepath.Join(scheduler.ProjectRoot, "bebop & config.toml")
	scheduler.InventoryPath = filepath.Join(scheduler.ProjectRoot, "hosts <inventory>.toml")
	scheduler.Executable = filepath.Join(scheduler.ProjectRoot, "bebop & binary")
	job := testScheduledJob(t)
	first, err := scheduler.DesiredPlists([]config.MaintenanceJob{job})
	if err != nil {
		t.Fatal(err)
	}
	second, err := scheduler.DesiredPlists([]config.MaintenanceJob{job})
	if err != nil || first[scheduler.PlistName(job.Name)] != second[scheduler.PlistName(job.Name)] {
		t.Fatalf("LaunchAgent generation was nondeterministic: %v", err)
	}
	plist := first[scheduler.PlistName(job.Name)]
	if strings.Contains(plist, "/bin/sh -c") || strings.Contains(plist, "KeepAlive") || strings.Contains(plist, "RunAtLoad") || !strings.Contains(plist, "<key>ProgramArguments</key>") || !strings.Contains(plist, "project &amp; &lt;space&gt;") {
		t.Fatalf("unsafe or unescaped LaunchAgent plist: %s", plist)
	}
	if !strings.Contains(plist, "<key>StartCalendarInterval</key>") || !strings.Contains(plist, "<key>Hour</key>\n    <integer>3</integer>") || !strings.Contains(plist, "<key>Minute</key>\n    <integer>0</integer>") {
		t.Fatalf("daily schedule did not compile: %s", plist)
	}
	if err := validatePlistXML(plist); err != nil {
		t.Fatal(err)
	}
}

func TestLaunchdDailyPlistGolden(t *testing.T) {
	scheduler := Launchd{
		LaunchAgentDirectory: "/Users/alice/Library/LaunchAgents",
		ProjectRoot:          "/Users/alice/src/bebop-project",
		ProjectID:            "0123456789ab",
		ConfigPath:           "/Users/alice/src/bebop-project/bebop.toml",
		InventoryPath:        "/Users/alice/src/bebop-project/bebop.hosts.toml",
		Executable:           "/usr/local/bin/bebop",
		Home:                 "/Users/alice",
		UID:                  501,
		Platform:             "darwin",
	}
	schedule, err := config.ParseMaintenanceSchedule("daily@03:05")
	if err != nil {
		t.Fatal(err)
	}
	plists, err := scheduler.DesiredPlists([]config.MaintenanceJob{{Name: "nightly-backup", Type: "backup", Target: "pi", Enabled: true, Schedule: schedule}})
	if err != nil {
		t.Fatal(err)
	}
	const expected = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<!-- Managed by Bebop. Do not edit; run bebop maintenance install. -->
<dict>
  <key>Label</key>
  <string>com.bebop.0123456789ab.maintenance.nightly-backup</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/bebop</string>
    <string>maintenance</string>
    <string>run</string>
    <string>--scheduled</string>
    <string>--config</string>
    <string>/Users/alice/src/bebop-project/bebop.toml</string>
    <string>--inventory</string>
    <string>/Users/alice/src/bebop-project/bebop.hosts.toml</string>
    <string>nightly-backup</string>
  </array>
  <key>WorkingDirectory</key>
  <string>/Users/alice/src/bebop-project</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/alice</string>
    <key>PATH</key>
    <string>/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>ProcessType</key>
  <string>Background</string>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key>
    <integer>3</integer>
    <key>Minute</key>
    <integer>5</integer>
  </dict>
</dict>
</plist>
`
	if actual := plists[scheduler.PlistName("nightly-backup")]; actual != expected {
		t.Fatalf("LaunchAgent plist changed unexpectedly:\n%s", actual)
	}
}

func TestLaunchdCompilesPortableSchedulesAndWeekdays(t *testing.T) {
	scheduler, _ := testLaunchd(t)
	for _, test := range []struct {
		schedule string
		contains string
	}{
		{"hourly", "<key>StartInterval</key>\n  <integer>3600</integer>"},
		{"daily@00:00", "<key>Hour</key>\n    <integer>0</integer>"},
		{"daily@23:59", "<key>Minute</key>\n    <integer>59</integer>"},
	} {
		schedule, err := config.ParseMaintenanceSchedule(test.schedule)
		if err != nil {
			t.Fatal(err)
		}
		job := testScheduledJob(t)
		job.Schedule = schedule
		plists, err := scheduler.DesiredPlists([]config.MaintenanceJob{job})
		if err != nil || !strings.Contains(plists[scheduler.PlistName(job.Name)], test.contains) {
			t.Fatalf("schedule %s = %q %v", test.schedule, plists[scheduler.PlistName(job.Name)], err)
		}
	}
	for weekday, want := range map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6} {
		schedule, err := config.ParseMaintenanceSchedule("weekly@" + weekday + "@23:59")
		if err != nil {
			t.Fatal(err)
		}
		job := testScheduledJob(t)
		job.Schedule = schedule
		plists, err := scheduler.DesiredPlists([]config.MaintenanceJob{job})
		if err != nil || !strings.Contains(plists[scheduler.PlistName(job.Name)], "<key>Weekday</key>\n    <integer>"+strconv.Itoa(want)+"</integer>") {
			t.Fatalf("weekday %s = %q %v", weekday, plists[scheduler.PlistName(job.Name)], err)
		}
	}
}

func TestLaunchdStatusDetectsDriftRelocationAndDisabledJobs(t *testing.T) {
	scheduler, loaded := testLaunchd(t)
	job := testScheduledJob(t)
	plists, err := scheduler.DesiredPlists([]config.MaintenanceJob{job})
	if err != nil {
		t.Fatal(err)
	}
	for name, contents := range plists {
		if err := os.WriteFile(filepath.Join(scheduler.LaunchAgentDirectory, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loaded[scheduler.Label(job.Name)] = true
	statuses, err := scheduler.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || len(statuses) != 1 || statuses[0].State != "current" || !statuses[0].Loaded || statuses[0].DesiredFingerprint == "" {
		t.Fatalf("current status = %#v %v", statuses, err)
	}
	filename := filepath.Join(scheduler.LaunchAgentDirectory, scheduler.PlistName(job.Name))
	if err := os.WriteFile(filename, []byte("manual edit"), 0o644); err != nil {
		t.Fatal(err)
	}
	statuses, err = scheduler.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("tampered status = %#v %v", statuses, err)
	}
	if err := os.WriteFile(filename, []byte(plists[scheduler.PlistName(job.Name)]), 0o644); err != nil {
		t.Fatal(err)
	}
	changed := job
	changed.Schedule, _ = config.ParseMaintenanceSchedule("daily@04:00")
	statuses, err = scheduler.Status(context.Background(), []config.MaintenanceJob{changed})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("policy drift status = %#v %v", statuses, err)
	}
	changedScheduler := scheduler
	changedScheduler.Executable = filepath.Join(t.TempDir(), "moved bebop")
	statuses, err = changedScheduler.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("binary relocation status = %#v %v", statuses, err)
	}
	moved := scheduler
	moved.ProjectRoot = filepath.Join(t.TempDir(), "moved project")
	moved.ProjectID = SchedulerProjectID(moved.ProjectRoot)
	moved.ConfigPath = filepath.Join(moved.ProjectRoot, "bebop.toml")
	statuses, err = moved.Status(context.Background(), []config.MaintenanceJob{job})
	if err != nil || statuses[0].State != "missing" {
		t.Fatalf("project relocation status = %#v %v", statuses, err)
	}
	disabled := job
	disabled.Enabled = false
	statuses, err = scheduler.Status(context.Background(), []config.MaintenanceJob{disabled})
	if err != nil || statuses[0].State != "stale" {
		t.Fatalf("disabled installed status = %#v %v", statuses, err)
	}
}

func TestLaunchdInstallReconcilesOwnedFilesAndRefusesSymlinks(t *testing.T) {
	scheduler, loaded := testLaunchd(t)
	job := testScheduledJob(t)
	unrelated := filepath.Join(scheduler.LaunchAgentDirectory, "com.example.unrelated.plist")
	if err := os.WriteFile(unrelated, []byte("unrelated"), 0o644); err != nil {
		t.Fatal(err)
	}
	foreignName := scheduler.Label("foreign") + ".plist"
	foreign := filepath.Join(scheduler.LaunchAgentDirectory, foreignName)
	if err := os.WriteFile(foreign, []byte("<plist><dict><string>"+scheduler.ConfigPath+"</string></dict></plist>"), 0o644); err != nil {
		t.Fatal(err)
	}
	changes, err := scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false)
	if err != nil || len(changes) != 1 || changes[0].Action != "install" || !loaded[scheduler.Label(job.Name)] {
		t.Fatalf("install = %#v %v", changes, err)
	}
	changes, err = scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false)
	if err != nil || len(changes) != 0 {
		t.Fatalf("second install = %#v %v", changes, err)
	}
	changes, err = scheduler.Install(context.Background(), nil, false)
	if err != nil || len(changes) != 1 || changes[0].Action != "remove" {
		t.Fatalf("obsolete reconciliation = %#v %v", changes, err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated LaunchAgent was touched: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatalf("unmarked project-prefixed LaunchAgent was touched: %v", err)
	}
	if _, err := scheduler.Uninstall(context.Background(), []config.MaintenanceJob{job}); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(scheduler.LaunchAgentDirectory, scheduler.PlistName(job.Name))); err != nil {
		t.Skipf("symlink test unavailable: %v", err)
	}
	if _, err := scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false); err == nil {
		t.Fatal("LaunchAgent symlink was accepted")
	}
	contents, err := os.ReadFile(target)
	if err != nil || string(contents) != "outside" {
		t.Fatalf("symlink target was modified: %q %v", contents, err)
	}
}

func TestLaunchdRefusesInvalidPlistValidationResult(t *testing.T) {
	scheduler, _ := testLaunchd(t)
	job := testScheduledJob(t)
	originalRun := scheduler.run
	scheduler.run = func(ctx context.Context, program string, arguments ...string) (string, error) {
		if program == scheduler.Plutil {
			return "invalid plist", errors.New("plutil rejected plist")
		}
		return originalRun(ctx, program, arguments...)
	}
	if _, err := scheduler.Install(context.Background(), []config.MaintenanceJob{job}, false); err == nil || !strings.Contains(err.Error(), "validate LaunchAgent plist") {
		t.Fatalf("invalid plist validation result = %v", err)
	}
	if _, err := os.Stat(filepath.Join(scheduler.LaunchAgentDirectory, scheduler.PlistName(job.Name))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unvalidated plist was installed: %v", err)
	}
}

func TestLaunchdProjectsAndResolverDoNotCollide(t *testing.T) {
	first, _ := testLaunchd(t)
	second, _ := testLaunchd(t)
	second.ProjectRoot = filepath.Join(t.TempDir(), "another-project")
	second.ProjectID = SchedulerProjectID(second.ProjectRoot)
	second.ConfigPath = filepath.Join(second.ProjectRoot, "bebop.toml")
	job := testScheduledJob(t)
	if first.Label(job.Name) == second.Label(job.Name) || first.PlistName(job.Name) == second.PlistName(job.Name) {
		t.Fatal("two projects collided on a LaunchAgent identity")
	}
	for _, test := range []struct {
		platform string
		want     string
	}{
		{"linux", "systemd-user"}, {"darwin", "launchd"}, {"windows", "unsupported"},
	} {
		adapter, err := ResolveScheduler(SchedulerContext{Platform: test.platform, ProjectRoot: first.ProjectRoot, ProjectID: first.ProjectID, ConfigPath: first.ConfigPath, InventoryPath: first.InventoryPath, Executable: first.Executable, Home: first.Home, UID: first.UID})
		if err != nil || adapter.Backend() != test.want {
			t.Fatalf("resolver %s = %#v %v", test.platform, adapter, err)
		}
	}
}

func TestLaunchdCapabilityClassifiesUnavailableDomain(t *testing.T) {
	scheduler, _ := testLaunchd(t)
	scheduler.run = func(context.Context, string, ...string) (string, error) {
		return "domain unavailable", errors.New("not found")
	}
	capability, detail := scheduler.Capability(context.Background())
	if capability != SchedulerUnavailable || !strings.Contains(detail, "domain") {
		t.Fatalf("capability = %s %q", capability, detail)
	}
}

func testLaunchd(t *testing.T) (Launchd, map[string]bool) {
	t.Helper()
	directory := t.TempDir()
	launchAgents := filepath.Join(directory, "Library", "LaunchAgents")
	if err := os.MkdirAll(launchAgents, 0o700); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(directory, "project")
	loaded := map[string]bool{}
	scheduler := Launchd{LaunchAgentDirectory: launchAgents, ProjectRoot: project, ProjectID: SchedulerProjectID(project), ConfigPath: filepath.Join(project, "bebop.toml"), InventoryPath: filepath.Join(project, "bebop.hosts.toml"), Executable: filepath.Join(project, "bebop"), Home: directory, UID: 501, Platform: "darwin", Launchctl: "fake-launchctl", Plutil: "fake-plutil"}
	scheduler.run = func(_ context.Context, program string, arguments ...string) (string, error) {
		if program == scheduler.Plutil {
			return "", nil
		}
		if len(arguments) >= 2 && arguments[0] == "print" {
			if arguments[1] == scheduler.Domain() {
				return "domain", nil
			}
			label := strings.TrimPrefix(arguments[1], scheduler.Domain()+"/")
			if loaded[label] {
				return "service", nil
			}
			return "Could not find service", errors.New("not found")
		}
		if len(arguments) >= 2 && arguments[0] == "bootstrap" {
			filename := arguments[len(arguments)-1]
			loaded[strings.TrimSuffix(filepath.Base(filename), ".plist")] = true
			return "", nil
		}
		if len(arguments) >= 2 && arguments[0] == "bootout" {
			label := strings.TrimPrefix(arguments[1], scheduler.Domain()+"/")
			if !loaded[label] {
				return "Could not find service", errors.New("not found")
			}
			delete(loaded, label)
			return "", nil
		}
		return "", nil
	}
	return scheduler, loaded
}
