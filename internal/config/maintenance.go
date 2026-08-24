package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/target"
)

const MaintenanceSchemaVersion = 1

// Maintenance is intentionally controller-side policy. Jobs are typed Bebop
// operations, never arbitrary commands or target-side scheduler instructions.
type Maintenance struct {
	Version           int              `toml:"version" json:"version"`
	HistoryDirectory  string           `toml:"history_dir" json:"history_dir"`
	HistoryMaxEntries int              `toml:"history_max_entries" json:"history_max_entries"`
	Jobs              []MaintenanceJob `toml:"-" json:"jobs"`
}

// MaintenanceJob is one independently schedulable operation. Target accepts
// an inventory alias, local, or the existing safe literal target syntax.
type MaintenanceJob struct {
	Name            string               `toml:"name" json:"name"`
	Type            string               `toml:"type" json:"type"`
	Target          string               `toml:"target" json:"target"`
	Service         string               `toml:"service,omitempty" json:"service,omitempty"`
	Enabled         bool                 `toml:"enabled" json:"enabled"`
	Schedule        MaintenanceSchedule  `toml:"-" json:"schedule"`
	Window          *MaintenanceWindow   `toml:"window,omitempty" json:"window,omitempty"`
	Retention       MaintenanceRetention `toml:"retention" json:"retention"`
	RefreshMetadata bool                 `toml:"refresh_metadata,omitempty" json:"refresh_metadata,omitempty"`
}

// MaintenanceSchedule is portable policy, compiled to a native scheduler by
// an adapter. All schedules use the controller's local timezone in M7.
type MaintenanceSchedule struct {
	Kind    string `json:"kind"`
	At      string `json:"at,omitempty"`
	Weekday string `json:"weekday,omitempty"`
}

// MaintenanceWindow permits a job to start only within a local controller
// time-of-day interval. It is optional for every job.
type MaintenanceWindow struct {
	Start string `toml:"start" json:"start"`
	End   string `toml:"end" json:"end"`
}

// MaintenanceRetention is deliberately small. It only controls verified
// snapshots created by the same maintenance job scope.
type MaintenanceRetention struct {
	KeepLast int `toml:"keep_last,omitempty" json:"keep_last,omitempty"`
}

type rawMaintenance struct {
	Version           *int                `toml:"version"`
	HistoryDirectory  *string             `toml:"history_dir"`
	HistoryMaxEntries *int                `toml:"history_max_entries"`
	Jobs              []rawMaintenanceJob `toml:"jobs"`
}

type rawMaintenanceJob struct {
	Name            *string                 `toml:"name"`
	Type            *string                 `toml:"type"`
	Target          *string                 `toml:"target"`
	Service         *string                 `toml:"service"`
	Enabled         *bool                   `toml:"enabled"`
	Schedule        *string                 `toml:"schedule"`
	Window          *MaintenanceWindow      `toml:"window"`
	Retention       rawMaintenanceRetention `toml:"retention"`
	RefreshMetadata *bool                   `toml:"refresh_metadata"`
}

type rawMaintenanceRetention struct {
	KeepLast *int `toml:"keep_last"`
}

func decodeMaintenance(raw rawMaintenance) (Maintenance, error) {
	result := Maintenance{HistoryDirectory: DefaultMaintenanceHistoryDirectory, HistoryMaxEntries: DefaultMaintenanceHistoryMaxEntries}
	if raw.Version != nil {
		result.Version = *raw.Version
	}
	if raw.HistoryDirectory != nil {
		result.HistoryDirectory = *raw.HistoryDirectory
	}
	if raw.HistoryMaxEntries != nil {
		result.HistoryMaxEntries = *raw.HistoryMaxEntries
	}
	for index, rawJob := range raw.Jobs {
		job := MaintenanceJob{Enabled: true}
		if rawJob.Name != nil {
			job.Name = *rawJob.Name
		}
		if rawJob.Type != nil {
			job.Type = *rawJob.Type
		}
		if rawJob.Target != nil {
			job.Target = *rawJob.Target
		}
		if rawJob.Service != nil {
			job.Service = *rawJob.Service
		}
		if rawJob.Enabled != nil {
			job.Enabled = *rawJob.Enabled
		}
		if rawJob.Schedule == nil {
			return Maintenance{}, fmt.Errorf("maintenance.jobs[%d].schedule is required", index)
		}
		schedule, err := ParseMaintenanceSchedule(*rawJob.Schedule)
		if err != nil {
			return Maintenance{}, fmt.Errorf("maintenance.jobs[%d].schedule %w", index, err)
		}
		job.Schedule = schedule
		job.Window = rawJob.Window
		if rawJob.Retention.KeepLast != nil {
			job.Retention.KeepLast = *rawJob.Retention.KeepLast
		}
		if rawJob.RefreshMetadata != nil {
			job.RefreshMetadata = *rawJob.RefreshMetadata
		}
		result.Jobs = append(result.Jobs, job)
	}
	sort.Slice(result.Jobs, func(i, j int) bool { return result.Jobs[i].Name < result.Jobs[j].Name })
	return result, nil
}

func ValidateMaintenance(maintenance Maintenance) error {
	if maintenance.Version != MaintenanceSchemaVersion {
		return fmt.Errorf("maintenance.version must be %d", MaintenanceSchemaVersion)
	}
	if err := ValidateControllerRelativePath(maintenance.HistoryDirectory, false); err != nil {
		return fmt.Errorf("maintenance.history_dir %w", err)
	}
	if maintenance.HistoryMaxEntries < 1 || maintenance.HistoryMaxEntries > 100_000 {
		return fmt.Errorf("maintenance.history_max_entries must be between 1 and 100000")
	}
	seen := map[string]bool{}
	for _, job := range maintenance.Jobs {
		if !serviceNamePattern.MatchString(job.Name) {
			return fmt.Errorf("maintenance job name must be 1-63 lowercase letters, numbers, or hyphens and start with a letter")
		}
		if seen[job.Name] {
			return fmt.Errorf("maintenance job names must be unique")
		}
		seen[job.Name] = true
		if job.Type != "backup" && job.Type != "doctor" && job.Type != "update-check" {
			return fmt.Errorf("maintenance job %s type must be backup, doctor, or update-check", job.Name)
		}
		if err := validateMaintenanceTarget(job.Target); err != nil {
			return fmt.Errorf("maintenance job %s target %w", job.Name, err)
		}
		if job.Type == "backup" {
			if !serviceNamePattern.MatchString(job.Service) {
				return fmt.Errorf("maintenance backup job %s requires a safe service name", job.Name)
			}
		} else if job.Service != "" {
			return fmt.Errorf("maintenance job %s service is supported only for backup", job.Name)
		}
		if job.RefreshMetadata && job.Type != "update-check" {
			return fmt.Errorf("maintenance job %s refresh_metadata is supported only for update-check", job.Name)
		}
		if _, err := ParseMaintenanceSchedule(job.Schedule.String()); err != nil {
			return fmt.Errorf("maintenance job %s schedule %w", job.Name, err)
		}
		if job.Window != nil {
			if _, err := ParseMaintenanceTime(job.Window.Start); err != nil {
				return fmt.Errorf("maintenance job %s window.start %w", job.Name, err)
			}
			if _, err := ParseMaintenanceTime(job.Window.End); err != nil {
				return fmt.Errorf("maintenance job %s window.end %w", job.Name, err)
			}
			if job.Window.Start == job.Window.End {
				return fmt.Errorf("maintenance job %s window start and end must differ", job.Name)
			}
		}
		if job.Retention.KeepLast < 0 || job.Retention.KeepLast > 100_000 {
			return fmt.Errorf("maintenance job %s retention.keep_last must be between 1 and 100000 when set", job.Name)
		}
		if job.Type != "backup" && job.Retention.KeepLast != 0 {
			return fmt.Errorf("maintenance job %s retention is supported only for backup", job.Name)
		}
	}
	return nil
}

func validateMaintenanceTarget(value string) error {
	if value == "" {
		return fmt.Errorf("must name an inventory host, local, or a literal target")
	}
	if value == "local" || strings.Contains(value, "://") {
		if _, err := target.Parse(value); err != nil {
			return err
		}
		return nil
	}
	if !namePattern.MatchString(value) {
		return fmt.Errorf("must be a safe inventory alias or target")
	}
	return nil
}

// ParseMaintenanceSchedule accepts a deliberately small portable grammar:
// hourly, daily@HH:MM, and weekly@mon@HH:MM through weekly@sun@HH:MM.
func ParseMaintenanceSchedule(value string) (MaintenanceSchedule, error) {
	if value == "hourly" {
		return MaintenanceSchedule{Kind: "hourly"}, nil
	}
	if strings.HasPrefix(value, "daily@") {
		at := strings.TrimPrefix(value, "daily@")
		if _, err := ParseMaintenanceTime(at); err != nil {
			return MaintenanceSchedule{}, err
		}
		return MaintenanceSchedule{Kind: "daily", At: at}, nil
	}
	parts := strings.Split(value, "@")
	if len(parts) == 3 && parts[0] == "weekly" {
		weekday := strings.ToLower(parts[1])
		if !validMaintenanceWeekday(weekday) {
			return MaintenanceSchedule{}, fmt.Errorf("must use mon, tue, wed, thu, fri, sat, or sun")
		}
		if _, err := ParseMaintenanceTime(parts[2]); err != nil {
			return MaintenanceSchedule{}, err
		}
		return MaintenanceSchedule{Kind: "weekly", Weekday: weekday, At: parts[2]}, nil
	}
	return MaintenanceSchedule{}, fmt.Errorf("must be hourly, daily@HH:MM, or weekly@day@HH:MM")
}

func (schedule MaintenanceSchedule) String() string {
	switch schedule.Kind {
	case "hourly":
		return "hourly"
	case "daily":
		return "daily@" + schedule.At
	case "weekly":
		return "weekly@" + schedule.Weekday + "@" + schedule.At
	default:
		return ""
	}
}

func ParseMaintenanceTime(value string) (time.Duration, error) {
	if len(value) != 5 || value[2] != ':' {
		return 0, fmt.Errorf("must use HH:MM in 24-hour time")
	}
	parsed, err := time.Parse("15:04", value)
	if err != nil || parsed.Format("15:04") != value {
		return 0, fmt.Errorf("must use HH:MM in 24-hour time")
	}
	return time.Duration(parsed.Hour())*time.Hour + time.Duration(parsed.Minute())*time.Minute, nil
}

func validMaintenanceWeekday(value string) bool {
	for _, weekday := range []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"} {
		if value == weekday {
			return true
		}
	}
	return false
}

// Fingerprint is deterministic policy provenance. It deliberately excludes
// source paths, installation timestamps, and current scheduler state.
func (job MaintenanceJob) Fingerprint() (string, error) {
	encoded, err := json.Marshal(job)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
