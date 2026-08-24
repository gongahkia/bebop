// Package notification turns safe, structured operational outcomes into local
// events and outbound-only delivery attempts. It has no target transport and
// no provider-specific operation logic.
package notification

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const EventSchemaVersion = 1

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Error    Severity = "error"
	Recovery Severity = "recovery"
)

type Event struct {
	SchemaVersion int       `json:"schema_version"`
	EventID       string    `json:"event_id"`
	Type          string    `json:"type"`
	Severity      Severity  `json:"severity"`
	OccurredAt    time.Time `json:"occurred_at"`
	Fingerprint   string    `json:"fingerprint"`
	Origin        string    `json:"origin"`
	Target        string    `json:"target"`
	Job           string    `json:"job,omitempty"`
	Service       string    `json:"service,omitempty"`
	Resource      string    `json:"resource,omitempty"`
	Summary       string    `json:"summary"`
	Details       Details   `json:"details,omitempty"`
	Test          bool      `json:"test,omitempty"`
}

// Details is intentionally bounded and contains only logical operational
// identifiers/counts. It excludes raw errors, target command output, secrets,
// controller filesystem paths, and target machine identity.
type Details struct {
	Category        string `json:"category,omitempty"`
	SnapshotID      string `json:"snapshot_id,omitempty"`
	Updates         int    `json:"updates,omitempty"`
	SecurityUpdates int    `json:"security_updates,omitempty"`
	State           string `json:"state,omitempty"`
}

// Operation is the notification-facing projection of maintenance execution.
// maintenance maps its private result types into this independent structure to
// keep this package downstream from all operational modules.
type Operation struct {
	RunID            string
	Job              string
	Operation        string
	Target           string
	Service          string
	Origin           string
	Result           string
	OccurredAt       time.Time
	FailureCategory  string
	SnapshotID       string
	Updates          int
	SecurityUpdates  int
	RetentionFailure bool
	Reason           string
	Findings         []Finding
}

// Finding carries the stable doctor diagnostic code and its normalized state.
// It intentionally omits message text, which may be volatile or sensitive.
type Finding struct {
	Code   string
	Status string
}

// Derive converts one operation outcome into deterministic issue observations
// plus distinct event occurrences. The returned order is stable by type,
// resource, and fingerprint.
func Derive(operation Operation) ([]Event, error) {
	if operation.Job == "" || operation.Operation == "" || operation.Target == "" {
		return nil, fmt.Errorf("notification operation requires job, operation, and target")
	}
	now := operation.OccurredAt.UTC()
	if now.IsZero() {
		return nil, fmt.Errorf("notification operation requires occurrence time")
	}
	result := make([]Event, 0)
	add := func(event Event) {
		event.SchemaVersion = EventSchemaVersion
		event.OccurredAt = now
		event.Origin = operation.Origin
		event.Target = operation.Target
		event.Job = operation.Job
		if event.Service == "" {
			event.Service = operation.Service
		}
		event.EventID = eventID(now)
		result = append(result, event)
	}
	switch operation.Operation {
	case "backup":
		if operation.Result == "success" {
			add(newEvent("backup.succeeded", Info, operation, "backup", "success", "Backup completed", Details{SnapshotID: operation.SnapshotID}))
			add(newEvent("maintenance.recovered", Recovery, operation, "backup", "failure", "Backup recovered", Details{Category: "backup"}))
		} else if operation.RetentionFailure {
			add(newEvent("backup.retention_failed", Error, operation, "backup", "failure", "Backup completed but retention failed", Details{Category: "retention", SnapshotID: operation.SnapshotID}))
		} else if operation.Result != "skipped" {
			category := cleanFailureCategory(operation.FailureCategory)
			add(newEvent("backup.failed", Error, operation, "backup", "failure", "Backup failed", Details{Category: category}))
		}
	case "doctor":
		for _, finding := range operation.Findings {
			if finding.Code == "" {
				continue
			}
			result = append(result, eventForFinding(operation, finding, now))
		}
		if len(operation.Findings) == 0 && operation.Result != "success" && operation.Result != "skipped" {
			category := cleanFailureCategory(operation.FailureCategory)
			add(newEvent("doctor.failed", Error, operation, "doctor", "failure", "Doctor check failed", Details{Category: category}))
		}
	case "update-check":
		if operation.Result == "success" && operation.Updates > 0 {
			add(newEvent("updates.available", Info, operation, "updates", "available", "Package updates are available", Details{Category: "available", Updates: operation.Updates, SecurityUpdates: operation.SecurityUpdates}))
		} else if operation.Result == "success" {
			add(newEvent("updates.cleared", Recovery, operation, "updates", "available", "No package updates are available", Details{Category: "available"}))
		} else if operation.Result != "skipped" {
			category := cleanFailureCategory(operation.FailureCategory)
			add(newEvent("maintenance.failed", Error, operation, "maintenance", "failure", "Update check failed", Details{Category: category}))
		}
	default:
		if operation.Result == "skipped" {
			add(newEvent("maintenance.skipped", Info, operation, "maintenance", nonEmpty(operation.Reason, "skipped"), "Maintenance job skipped", Details{Category: nonEmpty(operation.Reason, "skipped")}))
		} else if operation.Result != "success" {
			category := cleanFailureCategory(operation.FailureCategory)
			add(newEvent("maintenance.failed", Error, operation, "maintenance", "failure", "Maintenance job failed", Details{Category: category}))
		} else {
			add(newEvent("maintenance.recovered", Recovery, operation, "maintenance", "failure", "Maintenance job recovered", Details{Category: "maintenance"}))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Type != result[j].Type {
			return result[i].Type < result[j].Type
		}
		if result[i].Resource != result[j].Resource {
			return result[i].Resource < result[j].Resource
		}
		return result[i].Fingerprint < result[j].Fingerprint
	})
	return result, nil
}

func eventForFinding(operation Operation, finding Finding, now time.Time) Event {
	finding.Code = cleanFindingCode(finding.Code)
	domain, failureType, recoveryType, resource := findingDomain(finding.Code)
	severity := Warning
	if finding.Status == "fail" {
		severity = Error
	}
	eventType := failureType
	summary := "Doctor warning"
	if domain == "doctor" && severity == Warning {
		eventType = "doctor.warning"
	}
	if severity == Error {
		summary = "Doctor check failed"
	}
	if finding.Status == "pass" {
		severity, eventType, summary = Recovery, recoveryType, "Doctor check recovered"
	}
	event := newEvent(eventType, severity, operation, domain, finding.Code, summary, Details{Category: finding.Code, State: finding.Status})
	event.SchemaVersion = EventSchemaVersion
	event.Resource = resource
	if domain == "service" {
		event.Service = resource
	}
	event.Fingerprint = IssueFingerprint(domain, operation.Target, operation.Job, operation.Service, resource, finding.Code)
	event.OccurredAt = now
	event.Origin, event.Target, event.Job = operation.Origin, operation.Target, operation.Job
	event.EventID = eventID(now)
	return event
}

func findingDomain(code string) (domain, failed, recovered, resource string) {
	switch {
	case strings.HasPrefix(code, "storage."):
		return "storage", "storage.failed", "storage.recovered", strings.TrimPrefix(code, "storage.")
	case strings.HasPrefix(code, "service."):
		return "service", "service.unhealthy", "service.recovered", strings.TrimPrefix(code, "service.")
	default:
		return "doctor", "doctor.failed", "doctor.recovered", ""
	}
}

func newEvent(eventType string, severity Severity, operation Operation, domain, category, summary string, details Details) Event {
	return Event{Type: eventType, Severity: severity, Fingerprint: IssueFingerprint(domain, operation.Target, operation.Job, operation.Service, "", category), Service: operation.Service, Summary: summary, Details: details}
}

// IssueFingerprint binds stable operational identity without run IDs,
// timestamps, summaries, host machine IDs, or any secret-bearing value.
func IssueFingerprint(domain, target, job, service, resource, category string) string {
	payload := struct {
		Domain   string `json:"domain"`
		Target   string `json:"target"`
		Job      string `json:"job"`
		Service  string `json:"service,omitempty"`
		Resource string `json:"resource,omitempty"`
		Category string `json:"category"`
	}{domain, target, job, service, resource, category}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func eventID(now time.Time) string {
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		// A timestamp-derived ID remains distinct enough for a single invocation;
		// fingerprinting never relies on it.
		return fmt.Sprintf("evt-%d", now.UnixNano())
	}
	return fmt.Sprintf("evt-%d-%s", now.UnixNano(), hex.EncodeToString(bytes))
}

func nonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

var safeFindingPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,127}$`)

func cleanFindingCode(value string) string {
	if safeFindingPattern.MatchString(value) {
		return value
	}
	return "unknown"
}

func cleanFailureCategory(value string) string {
	switch value {
	case "config_invalid", "target_unreachable", "target_authentication", "target_host_key", "target_timeout", "unsupported_os", "privilege_unavailable", "apply_locked", "apply_failed", "verification_failed", "operation_failed":
		return value
	default:
		return "operation_failed"
	}
}

func IsRecovery(event Event) bool { return event.Severity == Recovery }

func SeverityRank(severity Severity) int {
	switch severity {
	case Info:
		return 1
	case Warning:
		return 2
	case Error:
		return 3
	default:
		return 0
	}
}
