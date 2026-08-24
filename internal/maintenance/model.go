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
	"github.com/bebop-home/bebop/internal/notification"
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
	SnapshotID              string    `json:"snapshot_id,omitempty"`
	Resources               int       `json:"resources,omitempty"`
	StoredSize              int64     `json:"stored_size,omitempty"`
	RetentionDeleted        []string  `json:"retention_deleted,omitempty"`
	RetentionCorruptSkipped []string  `json:"retention_corrupt_skipped,omitempty"`
	DoctorPass              int       `json:"doctor_pass,omitempty"`
	DoctorWarn              int       `json:"doctor_warn,omitempty"`
	DoctorFail              int       `json:"doctor_fail,omitempty"`
	UpdatesAvailable        int       `json:"updates_available,omitempty"`
	SecurityUpdates         int       `json:"security_updates,omitempty"`
	SecurityClassification  string    `json:"security_classification,omitempty"`
	MetadataRefreshed       bool      `json:"metadata_refreshed,omitempty"`
	RetentionFailure        bool      `json:"retention_failure,omitempty"`
	Findings                []Finding `json:"findings,omitempty"`
	Reason                  string    `json:"reason,omitempty"`
}

// Finding mirrors only preflight's stable diagnostic code/status. Messages do
// not enter maintenance history or notification payloads.
type Finding struct {
	Code   string `json:"code"`
	Status string `json:"status"`
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

// Notifier is deliberately downstream from maintenance execution. It receives
// already-sanitized events and cannot change the operation result.
type Notifier interface {
	Process(context.Context, []notification.Event) ([]notification.DeliveryResult, error)
}

type InvocationResult struct {
	Record            Record                        `json:"record"`
	Notifications     []notification.DeliveryResult `json:"notifications,omitempty"`
	NotificationError string                        `json:"notification_error,omitempty"`
}

type Runner struct {
	Jobs     []config.MaintenanceJob
	Clock    func() time.Time
	History  History
	Locks    Locker
	Executor Executor
	Notifier Notifier
}

func (runner Runner) Run(ctx context.Context, name string, options RunOptions) (Record, error) {
	result, err := runner.RunDetailed(ctx, name, options)
	return result.Record, err
}

// RunDetailed preserves the operation result while exposing separate
// controller-local notification delivery information to the CLI.
func (runner Runner) RunDetailed(ctx context.Context, name string, options RunOptions) (InvocationResult, error) {
	job, found := findJob(runner.Jobs, name)
	if !found {
		return InvocationResult{}, fmt.Errorf("unknown maintenance job %q", name)
	}
	if runner.Clock == nil {
		runner.Clock = time.Now
	}
	if runner.Executor == nil {
		return InvocationResult{}, fmt.Errorf("maintenance runner has no operation executor")
	}
	if options.Origin == "" {
		options.Origin = "manual"
	}
	if options.Origin != "manual" && options.Origin != "scheduled" {
		return InvocationResult{}, fmt.Errorf("invalid maintenance invocation origin")
	}
	if options.IgnoreWindow && options.Origin == "scheduled" {
		return InvocationResult{}, fmt.Errorf("scheduled maintenance cannot ignore its maintenance window")
	}
	fingerprint, err := job.Fingerprint()
	if err != nil {
		return InvocationResult{}, err
	}
	started := runner.Clock().UTC()
	runID, err := newRunID(started)
	if err != nil {
		return InvocationResult{}, err
	}
	record := Record{SchemaVersion: HistorySchemaVersion, RunID: runID, Job: job.Name, JobFingerprint: fingerprint, Operation: job.Type, Target: job.Target, Origin: options.Origin, WindowOverride: options.IgnoreWindow, StartedAt: started}
	finish := func(result Result, details Details, runErr error) (InvocationResult, error) {
		record.FinishedAt = runner.Clock().UTC()
		record.Result = result
		record.Details = details
		if runErr != nil {
			record.Error = historyError(runErr)
		}
		if err := runner.History.Append(record); err != nil {
			if runErr != nil {
				return InvocationResult{Record: record}, fmt.Errorf("%w; also write maintenance history: %v", runErr, err)
			}
			return InvocationResult{Record: record}, fmt.Errorf("write maintenance history: %w", err)
		}
		invocation := InvocationResult{Record: record}
		if runner.Notifier != nil {
			events, deriveErr := notification.Derive(notificationOperation(record, runErr))
			if deriveErr != nil {
				invocation.NotificationError = "event derivation failed"
			} else {
				invocation.Notifications, deriveErr = runner.Notifier.Process(ctx, events)
				if deriveErr != nil {
					invocation.NotificationError = "notification delivery unavailable"
				}
			}
		}
		return invocation, runErr
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

func notificationOperation(record Record, operationErr error) notification.Operation {
	findings := make([]notification.Finding, 0, len(record.Details.Findings))
	for _, finding := range record.Details.Findings {
		findings = append(findings, notification.Finding{Code: finding.Code, Status: finding.Status})
	}
	return notification.Operation{RunID: record.RunID, Job: record.Job, Operation: record.Operation, Target: record.Target, Origin: record.Origin, Result: string(record.Result), OccurredAt: record.FinishedAt, FailureCategory: notificationFailureCategory(operationErr), SnapshotID: record.Details.SnapshotID, Updates: record.Details.UpdatesAvailable, SecurityUpdates: record.Details.SecurityUpdates, RetentionFailure: record.Details.RetentionFailure, Reason: record.Details.Reason, Findings: findings}
}

func notificationFailureCategory(err error) string {
	if err == nil {
		return ""
	}
	var categorized *errs.Error
	if errors.As(err, &categorized) {
		return string(categorized.Code)
	}
	return "operation_failed"
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
