//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/maintenance"
	"github.com/bebop-home/bebop/internal/notification"
)

func TestNotificationLocalWebhookDedupeRecoveryAndSecretSafety(t *testing.T) {
	var mutex sync.Mutex
	bodies := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		contents, _ := io.ReadAll(request.Body)
		mutex.Lock()
		bodies = append(bodies, string(contents))
		mutex.Unlock()
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	t.Setenv("BEBOP_INTEGRATION_WEBHOOK", server.URL)
	cfg := notificationIntegrationConfig(t, []config.NotificationSink{{Name: "webhook", Type: "webhook", URLEnv: "BEBOP_INTEGRATION_WEBHOOK"}, {Name: "events", Type: "file", Path: ".bebop/notifications/events.jsonl"}}, []config.NotificationRoute{{Name: "web", Sink: "webhook", Events: []string{"backup.failed"}, Recoveries: true}, {Name: "file", Sink: "events", Events: []string{"backup.failed"}, Recoveries: true}})
	service, err := notification.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC)
	failure, err := notification.Derive(notification.Operation{RunID: "run-one", Job: "nightly-backup", Operation: "backup", Target: "pi", Service: "hello", Origin: "scheduled", Result: "failure", OccurredAt: now, FailureCategory: "BEBOP_TEST_SECRET_DO_NOT_LEAK"})
	if err != nil {
		t.Fatal(err)
	}
	if results, err := service.Process(context.Background(), failure); err != nil || countResults(results, "delivered") != 2 {
		t.Fatalf("initial notification = %#v %v", results, err)
	}
	if results, err := service.Process(context.Background(), failure); err != nil || countResults(results, "suppressed") != 2 {
		t.Fatalf("duplicate notification = %#v %v", results, err)
	}
	restarted, err := notification.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if results, err := restarted.Process(context.Background(), failure); err != nil || countResults(results, "suppressed") != 2 {
		t.Fatalf("restart dedupe = %#v %v", results, err)
	}
	recovery, err := notification.Derive(notification.Operation{RunID: "run-two", Job: "nightly-backup", Operation: "backup", Target: "pi", Service: "hello", Origin: "scheduled", Result: "success", OccurredAt: now.Add(time.Hour), SnapshotID: "snapshot-safe"})
	if err != nil {
		t.Fatal(err)
	}
	if results, err := restarted.Process(context.Background(), recovery); err != nil || countResults(results, "delivered") != 2 {
		t.Fatalf("recovery notification = %#v %v", results, err)
	}
	mutex.Lock()
	captured := append([]string(nil), bodies...)
	mutex.Unlock()
	if len(captured) != 2 {
		t.Fatalf("webhook deliveries = %d, want failure + recovery", len(captured))
	}
	for _, body := range captured {
		if strings.Contains(body, "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
			t.Fatalf("webhook leaked secret: %s", body)
		}
	}
	file, err := os.ReadFile(filepath.Join(cfg.SourceDirectory(), ".bebop", "notifications", "events.jsonl"))
	if err != nil || strings.Contains(string(file), "BEBOP_TEST_SECRET_DO_NOT_LEAK") || strings.Count(string(file), "\n") != 2 {
		t.Fatalf("file sink = %q %v", file, err)
	}
	issues, err := notification.ExistingStore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	active, err := issues.ActiveIssues()
	if err != nil || len(active) != 0 {
		t.Fatalf("recovery left active issue: %#v %v", active, err)
	}
}

func TestNotificationDeliveryFailureDoesNotChangeSuccessfulMaintenance(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	t.Setenv("BEBOP_INTEGRATION_WEBHOOK", server.URL)
	cfg := notificationIntegrationConfig(t, []config.NotificationSink{{Name: "webhook", Type: "webhook", URLEnv: "BEBOP_INTEGRATION_WEBHOOK"}}, []config.NotificationRoute{{Name: "success", Sink: "webhook", Events: []string{"backup.succeeded"}}})
	processor, err := notification.NewService(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Maintenance = &config.Maintenance{Version: config.MaintenanceSchemaVersion, HistoryDirectory: ".bebop/history", HistoryMaxEntries: 10}
	schedule, _ := config.ParseMaintenanceSchedule("daily@03:00")
	job := config.MaintenanceJob{Name: "backup", Type: "backup", Target: "pi", Service: "hello", Enabled: true, Schedule: schedule}
	history, err := maintenance.NewHistory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	runner := maintenance.Runner{Jobs: []config.MaintenanceJob{job}, Clock: func() time.Time { return time.Date(2026, 8, 24, 3, 0, 0, 0, time.UTC) }, History: history, Locks: maintenance.LocalLocker{Directory: filepath.Join(cfg.SourceDirectory(), ".bebop", "maintenance", "locks")}, Executor: integrationMaintenanceExecutor{}, Notifier: processor}
	result, err := runner.RunDetailed(context.Background(), job.Name, maintenance.RunOptions{Origin: "scheduled"})
	if err != nil || result.Record.Result != maintenance.Success || len(result.Notifications) != 1 || result.Notifications[0].Result != "failed" {
		t.Fatalf("delivery failure changed successful operation: %#v %v", result, err)
	}
	records, err := history.List(job.Name)
	if err != nil || len(records) != 1 || records[0].Result != maintenance.Success {
		t.Fatalf("operation history changed by webhook failure: %#v %v", records, err)
	}
}

type integrationMaintenanceExecutor struct{}

func (integrationMaintenanceExecutor) Execute(context.Context, config.MaintenanceJob, maintenance.Invocation) (maintenance.Outcome, error) {
	return maintenance.Outcome{Result: maintenance.Success, Details: maintenance.Details{SnapshotID: "snapshot-safe"}}, nil
}

func notificationIntegrationConfig(t *testing.T, sinks []config.NotificationSink, routes []config.NotificationRoute) config.Config {
	t.Helper()
	cfg := config.WithSourceDirectory(config.Defaults(), t.TempDir())
	cfg.Notifications = &config.Notifications{Version: config.NotificationsSchemaVersion, Enabled: true, StateDirectory: ".bebop/notifications", HistoryMaxEntries: 20, Sinks: sinks, Routes: routes}
	return cfg
}

func countResults(results []notification.DeliveryResult, result string) int {
	count := 0
	for _, delivery := range results {
		if delivery.Result == result {
			count++
		}
	}
	return count
}
