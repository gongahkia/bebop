// Package maintenance adds controller-side scheduling policy around existing
// Bebop operations. It owns no target execution path: typed executors call the
// existing backup, inspection, and preflight services directly.
package maintenance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
)

const HistorySchemaVersion = 1

type Result string

const (
	Success Result = "success"
	Warning Result = "warning"
	Failure Result = "failure"
	Skipped Result = "skipped"
)

// Details is a bounded typed operation summary. It deliberately excludes raw
// terminal output and any source/secret input contents.
type Details struct {
	SnapshotID              string   `json:"snapshot_id,omitempty"`
	Resources               int      `json:"resources,omitempty"`
	StoredSize              int64    `json:"stored_size,omitempty"`
	RetentionDeleted        []string `json:"retention_deleted,omitempty"`
	RetentionCorruptSkipped []string `json:"retention_corrupt_skipped,omitempty"`
	DoctorPass              int      `json:"doctor_pass,omitempty"`
	DoctorWarn              int      `json:"doctor_warn,omitempty"`
	DoctorFail              int      `json:"doctor_fail,omitempty"`
	UpdatesAvailable        int      `json:"updates_available,omitempty"`
	SecurityUpdates         int      `json:"security_updates,omitempty"`
	SecurityClassification  string   `json:"security_classification,omitempty"`
	MetadataRefreshed       bool     `json:"metadata_refreshed,omitempty"`
	Reason                  string   `json:"reason,omitempty"`
}

// Record is immutable operational provenance. It is observational only; jobs,
// repositories, targets, and saved plans never depend on it for correctness.
type Record struct {
	SchemaVersion  int       `json:"schema_version"`
	RunID          string    `json:"run_id"`
	Job            string    `json:"job"`
	JobFingerprint string    `json:"job_fingerprint"`
	Operation      string    `json:"operation"`
	Target         string    `json:"target"`
	Origin         string    `json:"origin"`
	WindowOverride bool      `json:"window_override,omitempty"`
	StartedAt      time.Time `json:"started_at"`
	FinishedAt     time.Time `json:"finished_at"`
	Result         Result    `json:"result"`
	Details        Details   `json:"details,omitempty"`
	Error          string    `json:"error,omitempty"`
}

type Invocation struct {
	RunID          string
	JobFingerprint string
}

type Outcome struct {
	Result  Result
	Details Details
}

// Executor makes exactly one typed operation happen. It never receives an
// arbitrary command string, and it is deliberately injectable for unit tests.
type Executor interface {
	Execute(context.Context, config.MaintenanceJob, Invocation) (Outcome, error)
}

type RunOptions struct {
	Origin       string
	IgnoreWindow bool
}

type Runner struct {
	Jobs     []config.MaintenanceJob
	Clock    func() time.Time
	History  History
	Locks    Locker
	Executor Executor
}

func (runner Runner) Run(ctx context.Context, name string, options RunOptions) (Record, error) {
	job, found := findJob(runner.Jobs, name)
	if !found {
		return Record{}, fmt.Errorf("unknown maintenance job %q", name)
	}
	if runner.Clock == nil {
		runner.Clock = time.Now
	}
	if runner.Executor == nil {
		return Record{}, fmt.Errorf("maintenance runner has no operation executor")
	}
	if options.Origin == "" {
		options.Origin = "manual"
	}
	if options.Origin != "manual" && options.Origin != "scheduled" {
		return Record{}, fmt.Errorf("invalid maintenance invocation origin")
	}
	if options.IgnoreWindow && options.Origin == "scheduled" {
		return Record{}, fmt.Errorf("scheduled maintenance cannot ignore its maintenance window")
	}
	fingerprint, err := job.Fingerprint()
	if err != nil {
		return Record{}, err
	}
	started := runner.Clock().UTC()
	runID, err := newRunID(started)
	if err != nil {
		return Record{}, err
	}
	record := Record{SchemaVersion: HistorySchemaVersion, RunID: runID, Job: job.Name, JobFingerprint: fingerprint, Operation: job.Type, Target: job.Target, Origin: options.Origin, WindowOverride: options.IgnoreWindow, StartedAt: started}
	finish := func(result Result, details Details, runErr error) (Record, error) {
		record.FinishedAt = runner.Clock().UTC()
		record.Result = result
		record.Details = details
		if runErr != nil {
			record.Error = historyError(runErr)
		}
		if err := runner.History.Append(record); err != nil {
			if runErr != nil {
				return record, fmt.Errorf("%w; also write maintenance history: %v", runErr, err)
			}
			return record, fmt.Errorf("write maintenance history: %w", err)
		}
		return record, runErr
	}
	if !job.Enabled {
		return finish(Skipped, Details{Reason: "disabled"}, nil)
	}
	if !options.IgnoreWindow && !EligibleAt(job, started) {
		return finish(Skipped, Details{Reason: "outside-window"}, nil)
	}
	lock, err := runner.Locks.Acquire(job.Name)
	if err != nil {
		if errors.Is(err, ErrJobAlreadyRunning) {
			return finish(Skipped, Details{Reason: "already-running"}, nil)
		}
		return finish(Failure, Details{}, fmt.Errorf("acquire maintenance job lock: %w", err))
	}
	defer lock.Release()
	outcome, operationErr := runner.Executor.Execute(ctx, job, Invocation{RunID: runID, JobFingerprint: fingerprint})
	if outcome.Result == "" {
		outcome.Result = Success
	}
	if operationErr != nil && outcome.Result == Success {
		outcome.Result = Failure
	}
	return finish(outcome.Result, outcome.Details, operationErr)
}

// historyError intentionally does not persist raw remote stderr or arbitrary
// wrapped errors. Scheduler/journal output remains the diagnostic backend;
// history stores only a safe operational summary and cannot become a secret
// side channel.
func historyError(err error) string {
	var categorized *errs.Error
	if errors.As(err, &categorized) {
		return string(categorized.Code) + ": " + conciseError(errors.New(categorized.Message))
	}
	return "operation failed; inspect command output or scheduler journal"
}

// EligibleAt uses the controller's local wall clock. Start is inclusive and
// end is exclusive; windows crossing midnight use the same rule over two days.
func EligibleAt(job config.MaintenanceJob, now time.Time) bool {
	if job.Window == nil {
		return true
	}
	start, startErr := config.ParseMaintenanceTime(job.Window.Start)
	end, endErr := config.ParseMaintenanceTime(job.Window.End)
	if startErr != nil || endErr != nil || start == end {
		return false
	}
	local := now.In(time.Local)
	current := time.Duration(local.Hour())*time.Hour + time.Duration(local.Minute())*time.Minute + time.Duration(local.Second())*time.Second + time.Duration(local.Nanosecond())
	if start < end {
		return current >= start && current < end
	}
	return current >= start || current < end
}

func findJob(jobs []config.MaintenanceJob, name string) (config.MaintenanceJob, bool) {
	for _, job := range jobs {
		if job.Name == name {
			return job, true
		}
	}
	return config.MaintenanceJob{}, false
}

func newRunID(now time.Time) (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("run-%d-%s", now.UnixNano(), hex.EncodeToString(bytes)), nil
}
