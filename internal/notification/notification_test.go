package notification

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/config"
)

type captureSink struct {
	mu       sync.Mutex
	events   []Event
	outcomes []DeliveryOutcome
}

func (sink *captureSink) Deliver(_ context.Context, event Event) DeliveryOutcome {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	if len(sink.outcomes) == 0 {
		return DeliveryOutcome{Delivered: true, Attempts: 1}
	}
	outcome := sink.outcomes[0]
	sink.outcomes = sink.outcomes[1:]
	return outcome
}
func (sink *captureSink) count() int { sink.mu.Lock(); defer sink.mu.Unlock(); return len(sink.events) }

func TestDeriveUsesStableSecretSafeIssueFingerprints(t *testing.T) {
	first, err := Derive(Operation{RunID: "run-one", Job: "nightly-backup", Operation: "backup", Target: "pi", Origin: "scheduled", Result: "failure", OccurredAt: time.Unix(1, 0), FailureCategory: "BEBOP_TEST_SECRET_DO_NOT_LEAK"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Derive(Operation{RunID: "run-two", Job: "nightly-backup", Operation: "backup", Target: "pi", Origin: "scheduled", Result: "failure", OccurredAt: time.Unix(2, 0), FailureCategory: "target_unreachable"})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Type != "backup.failed" || first[0].Severity != Error || first[0].Fingerprint != second[0].Fingerprint || first[0].EventID == second[0].EventID {
		t.Fatalf("unexpected backup events: %#v %#v", first, second)
	}
	encoded, _ := json.Marshal(first)
	if strings.Contains(string(encoded), "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
		t.Fatalf("event leaked sentinel: %s", encoded)
	}
	doctor, err := Derive(Operation{RunID: "run", Job: "doctor", Operation: "doctor", Target: "pi", Origin: "scheduled", Result: "warning", OccurredAt: time.Unix(3, 0), Findings: []Finding{{Code: "storage.bulk", Status: "warn"}, {Code: "service.hello", Status: "warn"}, {Code: "ssh.config_invalid", Status: "warn"}}})
	if err != nil {
		t.Fatal(err)
	}
	types := map[string]bool{}
	for _, event := range doctor {
		types[event.Type] = true
	}
	if !types["storage.failed"] || !types["service.unhealthy"] || !types["doctor.warning"] {
		t.Fatalf("doctor findings did not derive typed events: %#v", doctor)
	}
	for _, test := range []struct {
		operation Operation
		want      string
	}{
		{Operation{RunID: "run", Job: "backup", Operation: "backup", Target: "pi", Origin: "scheduled", Result: "success", OccurredAt: time.Unix(4, 0)}, "backup.succeeded"},
		{Operation{RunID: "run", Job: "backup", Operation: "backup", Target: "pi", Origin: "scheduled", Result: "warning", OccurredAt: time.Unix(5, 0), RetentionFailure: true}, "backup.retention_failed"},
		{Operation{RunID: "run", Job: "doctor", Operation: "doctor", Target: "pi", Origin: "scheduled", Result: "failure", OccurredAt: time.Unix(6, 0), Findings: []Finding{{Code: "ssh.config_invalid", Status: "fail"}}}, "doctor.failed"},
		{Operation{RunID: "run", Job: "doctor", Operation: "doctor", Target: "pi", Origin: "scheduled", Result: "success", OccurredAt: time.Unix(7, 0), Findings: []Finding{{Code: "storage.bulk", Status: "pass"}}}, "storage.recovered"},
		{Operation{RunID: "run", Job: "updates", Operation: "update-check", Target: "pi", Origin: "scheduled", Result: "success", OccurredAt: time.Unix(8, 0), Updates: 2}, "updates.available"},
		{Operation{RunID: "run", Job: "updates", Operation: "update-check", Target: "pi", Origin: "scheduled", Result: "success", OccurredAt: time.Unix(9, 0)}, "updates.cleared"},
		{Operation{RunID: "run", Job: "updates", Operation: "update-check", Target: "pi", Origin: "scheduled", Result: "failure", OccurredAt: time.Unix(10, 0), FailureCategory: "target_unreachable"}, "maintenance.failed"},
		{Operation{RunID: "run", Job: "doctor", Operation: "custom", Target: "pi", Origin: "scheduled", Result: "skipped", OccurredAt: time.Unix(11, 0), Reason: "outside-window"}, "maintenance.skipped"},
	} {
		events, deriveErr := Derive(test.operation)
		if deriveErr != nil || len(events) == 0 || events[0].Type != test.want {
			t.Fatalf("derive %s: %#v %v", test.want, events, deriveErr)
		}
	}
}

func TestProcessDeduplicatesEscalatesRecoversAndPersists(t *testing.T) {
	cfg := testConfig(t, ".bebop/notifications")
	store, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	now := time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC)
	service := NewServiceForTest(*cfg.Notifications, store, map[string]Sink{"events": sink}, func() time.Time { return now })
	warning := testEvent(now, "doctor.warning", Warning, "doctor", "storage.bulk")
	results, err := service.Process(context.Background(), []Event{warning})
	if err != nil || len(results) != 1 || results[0].Result != "delivered" || sink.count() != 1 {
		t.Fatalf("first issue = %#v %v", results, err)
	}
	results, err = service.Process(context.Background(), []Event{warning})
	if err != nil || len(results) != 1 || results[0].Result != "suppressed" || sink.count() != 1 {
		t.Fatalf("repeat issue = %#v %v", results, err)
	}
	escalated := warning
	escalated.EventID = "evt-escalated"
	escalated.Type, escalated.Severity = "doctor.failed", Error
	results, err = service.Process(context.Background(), []Event{escalated})
	if err != nil || results[0].Result != "delivered" || sink.count() != 2 {
		t.Fatalf("escalation = %#v %v", results, err)
	}
	reloaded := NewServiceForTest(*cfg.Notifications, store, map[string]Sink{"events": sink}, func() time.Time { return now })
	results, err = reloaded.Process(context.Background(), []Event{escalated})
	if err != nil || results[0].Result != "suppressed" || sink.count() != 2 {
		t.Fatalf("restart persistence = %#v %v", results, err)
	}
	recovery := escalated
	recovery.EventID = "evt-recovery"
	recovery.Type, recovery.Severity, recovery.Summary = "doctor.recovered", Recovery, "Doctor recovered"
	results, err = reloaded.Process(context.Background(), []Event{recovery})
	if err != nil || len(results) != 1 || results[0].Result != "delivered" || sink.count() != 3 {
		t.Fatalf("recovery = %#v %v", results, err)
	}
	issues, err := store.ActiveIssues()
	if err != nil || len(issues) != 0 {
		t.Fatalf("recovered issue remained active: %#v %v", issues, err)
	}
	results, err = reloaded.Process(context.Background(), []Event{warning})
	if err != nil || results[0].Result != "delivered" || sink.count() != 4 {
		t.Fatalf("new issue after recovery = %#v %v", results, err)
	}
}

func TestProcessCooldownAndConcurrentDuplicateEvaluation(t *testing.T) {
	cfg := testConfig(t, ".bebop/notifications")
	cfg.Notifications.Routes[0].Cooldown = "1h"
	store, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	now := time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC)
	event := testEvent(now, "doctor.failed", Error, "doctor", "docker.unhealthy")
	services := []*Service{NewServiceForTest(*cfg.Notifications, store, map[string]Sink{"events": sink}, func() time.Time { return now }), NewServiceForTest(*cfg.Notifications, store, map[string]Sink{"events": sink}, func() time.Time { return now })}
	var group sync.WaitGroup
	for _, service := range services {
		group.Add(1)
		go func(service *Service) {
			defer group.Done()
			if _, err := service.Process(context.Background(), []Event{event}); err != nil {
				t.Errorf("process: %v", err)
			}
		}(service)
	}
	group.Wait()
	if sink.count() != 1 {
		t.Fatalf("concurrent first issue delivered %d times", sink.count())
	}
	within := event
	within.EventID, within.OccurredAt = "evt-within", now.Add(59*time.Minute)
	if results, err := services[0].Process(context.Background(), []Event{within}); err != nil || results[0].Result != "suppressed" {
		t.Fatalf("cooldown suppression = %#v %v", results, err)
	}
	after := event
	after.EventID, after.OccurredAt = "evt-after", now.Add(time.Hour)
	if results, err := services[0].Process(context.Background(), []Event{after}); err != nil || results[0].Result != "delivered" {
		t.Fatalf("cooldown boundary = %#v %v", results, err)
	}
}

func TestRouteFilteringSeverityAndRecoveryPolicy(t *testing.T) {
	cfg := testConfig(t, ".bebop/notifications")
	cfg.Notifications.Routes = []config.NotificationRoute{
		{Name: "errors", Sink: "events", Events: []string{"doctor.failed"}, Severities: []string{"error"}, Recoveries: false},
		{Name: "warnings", Sink: "events", Events: []string{"doctor.warning"}, Severities: []string{"warning"}, Recoveries: true},
	}
	store, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	service := NewServiceForTest(*cfg.Notifications, store, map[string]Sink{"events": sink}, time.Now)
	warning := testEvent(time.Now().UTC(), "doctor.warning", Warning, "doctor", "warning")
	if results, err := service.Process(context.Background(), []Event{warning}); err != nil || len(results) != 1 || results[0].Route != "warnings" || results[0].Result != "delivered" {
		t.Fatalf("warning route = %#v %v", results, err)
	}
	recovery := warning
	recovery.EventID, recovery.Type, recovery.Severity = "evt-warning-recovered", "doctor.recovered", Recovery
	if results, err := service.Process(context.Background(), []Event{recovery}); err != nil || len(results) != 1 || results[0].Route != "warnings" || results[0].Result != "delivered" {
		t.Fatalf("recovery policy = %#v %v", results, err)
	}
	errorEvent := testEvent(time.Now().UTC(), "doctor.failed", Error, "doctor", "error")
	if results, err := service.Process(context.Background(), []Event{errorEvent}); err != nil || len(results) != 1 || results[0].Route != "errors" {
		t.Fatalf("error route = %#v %v", results, err)
	}
	errorRecovery := errorEvent
	errorRecovery.EventID, errorRecovery.Type, errorRecovery.Severity = "evt-error-recovered", "doctor.recovered", Recovery
	if results, err := service.Process(context.Background(), []Event{errorRecovery}); err != nil || len(results) != 0 {
		t.Fatalf("disabled recovery route = %#v %v", results, err)
	}
}

func TestStateCorruptionAndTestEventDoNotAlterOperations(t *testing.T) {
	cfg := testConfig(t, ".bebop/notifications")
	store, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	sink := &captureSink{}
	service := NewServiceForTest(*cfg.Notifications, store, map[string]Sink{"events": sink}, time.Now)
	if _, err := service.Test(context.Background(), "events"); err != nil {
		t.Fatal(err)
	}
	issues, err := store.ActiveIssues()
	if err != nil || len(issues) != 0 {
		t.Fatalf("test event changed active state: %#v %v", issues, err)
	}
	if err := os.WriteFile(filepath.Join(store.Root(), "state.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Process(context.Background(), []Event{testEvent(time.Now().UTC(), "doctor.failed", Error, "doctor", "bad")}); err == nil || sink.count() != 1 {
		t.Fatalf("corrupt state processed events err=%v calls=%d", err, sink.count())
	}
}

func TestFileSinkIsSecretSafeAndRejectsSymlinkEscape(t *testing.T) {
	cfg := testConfig(t, ".bebop/notifications")
	cfg.Notifications.Sinks = []config.NotificationSink{{Name: "events", Type: "file", Path: ".bebop/notifications/events.jsonl"}}
	store, err := OpenStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	events, err := Derive(Operation{RunID: "run", Job: "backup", Operation: "backup", Target: "pi", Origin: "scheduled", Result: "failure", OccurredAt: time.Now().UTC(), FailureCategory: "BEBOP_TEST_SECRET_DO_NOT_LEAK"})
	if err != nil {
		t.Fatal(err)
	}
	if results, err := service.Process(context.Background(), events); err != nil || results[0].Result != "delivered" {
		t.Fatalf("file delivery = %#v %v", results, err)
	}
	contents, err := os.ReadFile(filepath.Join(store.Root(), "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(contents), "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
		t.Fatalf("file sink leaked secret: %s", contents)
	}
	for _, filename := range []string{filepath.Join(store.Root(), "state.json")} {
		stored, readErr := os.ReadFile(filename)
		if readErr != nil || strings.Contains(string(stored), "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
			t.Fatalf("notification state leaked secret: %q %v", stored, readErr)
		}
	}
	history, historyErr := store.DeliveryHistory()
	if historyErr != nil {
		t.Fatal(historyErr)
	}
	encodedHistory, _ := json.Marshal(history)
	if strings.Contains(string(encodedHistory), "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
		t.Fatalf("delivery history leaked secret: %s", encodedHistory)
	}
	if err := os.MkdirAll(filepath.Join(store.Root(), "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(store.Root(), "nested", "escape")); err != nil {
		t.Fatal(err)
	}
	cfg.Notifications.Sinks = []config.NotificationSink{{Name: "events", Type: "file", Path: ".bebop/notifications/nested/escape/events.jsonl"}}
	unsafe, err := NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	other := testEvent(time.Now().UTC(), "doctor.failed", Error, "doctor", "unsafe")
	results, err := unsafe.Process(context.Background(), []Event{other})
	if err != nil || results[0].Result != "failed" || results[0].Category != "unsafe_path" {
		t.Fatalf("symlink sink = %#v %v", results, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "events.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("sink followed symlink: %v", err)
	}
}

func testConfig(t *testing.T, stateDirectory string) config.Config {
	t.Helper()
	cfg := config.WithSourceDirectory(config.Defaults(), t.TempDir())
	cfg.Notifications = &config.Notifications{Version: config.NotificationsSchemaVersion, Enabled: true, StateDirectory: stateDirectory, HistoryMaxEntries: 20, Sinks: []config.NotificationSink{{Name: "events", Type: "file", Path: ".bebop/notifications/events.jsonl"}}, Routes: []config.NotificationRoute{{Name: "all", Sink: "events", Events: []string{"backup.failed", "doctor.warning", "doctor.failed", "storage.failed", "service.unhealthy", "maintenance.failed", "updates.available"}, Recoveries: true}}}
	return cfg
}

func testEvent(now time.Time, eventType string, severity Severity, domain, category string) Event {
	return Event{SchemaVersion: EventSchemaVersion, EventID: "evt-" + strings.ReplaceAll(eventType, ".", "-") + "-" + category, Type: eventType, Severity: severity, OccurredAt: now, Fingerprint: IssueFingerprint(domain, "pi", "doctor", "", "", category), Origin: "scheduled", Target: "pi", Job: "doctor", Summary: eventType, Details: Details{Category: category}}
}
