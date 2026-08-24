package config

import (
	"strings"
	"testing"
)

func TestMaintenanceSchemaIsStrictAndNormalized(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`version = 1

[maintenance]
version = 1
history_dir = ".bebop/history"
history_max_entries = 42

[[maintenance.jobs]]
name = "weekly-doctor"
type = "doctor"
target = "pi"
schedule = "weekly@sun@08:00"

[[maintenance.jobs]]
name = "nightly-backup"
type = "backup"
target = "pi"
service = "hello"
schedule = "daily@03:00"

[maintenance.jobs.window]
start = "02:00"
end = "05:00"

[maintenance.jobs.retention]
keep_last = 7

[[maintenance.jobs]]
name = "updates"
type = "update-check"
target = "ssh://user@host"
schedule = "hourly"
refresh_metadata = true
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Maintenance == nil || len(cfg.Maintenance.Jobs) != 3 || cfg.Maintenance.Jobs[0].Name != "nightly-backup" {
		t.Fatalf("maintenance jobs did not sort/decode: %#v", cfg.Maintenance)
	}
	backup := cfg.Maintenance.Jobs[0]
	if backup.Schedule.String() != "daily@03:00" || backup.Window == nil || backup.Retention.KeepLast != 7 {
		t.Fatalf("backup policy did not normalize: %#v", backup)
	}
	first, err := backup.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	second, err := backup.Fingerprint()
	if err != nil || first != second {
		t.Fatalf("maintenance job fingerprint is nondeterministic: %q %q %v", first, second, err)
	}
	for _, contents := range []string{
		"version=1\n[maintenance]\nversion=2\n",
		"version=1\n[maintenance]\nversion=1\n[[maintenance.jobs]]\nname='bad_name'\ntype='doctor'\ntarget='pi'\nschedule='daily@03:00'\n",
		"version=1\n[maintenance]\nversion=1\n[[maintenance.jobs]]\nname='backup'\ntype='backup'\ntarget='pi'\nschedule='daily@03:00'\n",
		"version=1\n[maintenance]\nversion=1\n[[maintenance.jobs]]\nname='updates'\ntype='update-check'\ntarget='pi'\nschedule='weekly@funday@03:00'\n",
		"version=1\n[maintenance]\nversion=1\n[[maintenance.jobs]]\nname='doctor'\ntype='doctor'\ntarget='pi'\nschedule='daily@03:00'\ncommand='unsafe'\n",
		"version=1\n[maintenance]\nversion=1\n[[maintenance.jobs]]\nname='doctor'\ntype='doctor'\ntarget='pi'\nschedule='daily@03:00'\n[maintenance.jobs.window]\nstart='02:00'\nend='02:00'\n",
		"version=1\n[maintenance]\nversion=1\n[[maintenance.jobs]]\nname='doctor'\ntype='doctor'\ntarget='pi'\nschedule='daily@03:00'\n[maintenance.jobs.retention]\nkeep_last=2\n",
	} {
		if _, err := Decode(strings.NewReader(contents)); err == nil {
			t.Fatalf("unsafe maintenance configuration was accepted: %s", contents)
		}
	}
}

func TestParseMaintenanceSchedule(t *testing.T) {
	for _, value := range []string{"hourly", "daily@00:00", "daily@23:59", "weekly@mon@03:00", "weekly@sun@23:59"} {
		parsed, err := ParseMaintenanceSchedule(value)
		if err != nil || parsed.String() != value {
			t.Fatalf("ParseMaintenanceSchedule(%q) = %#v, %v", value, parsed, err)
		}
	}
	for _, value := range []string{"daily@3:00", "daily@24:00", "weekly@mon@03:00:01", "weekly@monday@03:00", "cron:* * * * *"} {
		if _, err := ParseMaintenanceSchedule(value); err == nil {
			t.Fatalf("invalid schedule accepted: %q", value)
		}
	}
}

func TestMaintenancePolicyDoesNotChangeTargetPlanFingerprint(t *testing.T) {
	base := Defaults()
	before, err := Fingerprint(base)
	if err != nil {
		t.Fatal(err)
	}
	schedule, _ := ParseMaintenanceSchedule("daily@03:00")
	base.Maintenance = &Maintenance{Version: MaintenanceSchemaVersion, HistoryDirectory: ".bebop/history", HistoryMaxEntries: 100, Jobs: []MaintenanceJob{{Name: "doctor", Type: "doctor", Target: "pi", Enabled: true, Schedule: schedule}}}
	after, err := Fingerprint(base)
	if err != nil || before != after {
		t.Fatalf("controller maintenance policy changed target desired-state fingerprint: %q %q %v", before, after, err)
	}
}
