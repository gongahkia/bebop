package notification

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebhookRetriesOnlyTransientFailuresAndRedactsPayload(t *testing.T) {
	var requests atomic.Int32
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		bodyBytes := make([]byte, request.ContentLength)
		_, _ = request.Body.Read(bodyBytes)
		body = string(bodyBytes)
		if requests.Add(1) == 1 {
			writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	t.Setenv("BEBOP_TEST_WEBHOOK", server.URL)
	sink := WebhookSink{urlEnv: "BEBOP_TEST_WEBHOOK", client: newWebhookClient(), sleep: func(time.Duration) {}}
	events, err := Derive(Operation{RunID: "run", Job: "backup", Operation: "backup", Target: "pi", Origin: "scheduled", Result: "failure", OccurredAt: time.Now().UTC(), FailureCategory: "BEBOP_TEST_SECRET_DO_NOT_LEAK"})
	if err != nil {
		t.Fatal(err)
	}
	result := sink.Deliver(context.Background(), events[0])
	if !result.Delivered || result.Attempts != 2 || requests.Load() != 2 {
		t.Fatalf("transient retry = %#v requests=%d", result, requests.Load())
	}
	if strings.Contains(body, "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
		t.Fatalf("webhook payload leaked secret: %s", body)
	}
	var payload struct {
		SchemaVersion int   `json:"schema_version"`
		Event         Event `json:"event"`
	}
	if err := json.Unmarshal([]byte(body), &payload); err != nil || payload.SchemaVersion != EventSchemaVersion || payload.Event.Type != "backup.failed" {
		t.Fatalf("webhook payload = %#v %v", payload, err)
	}

	requests.Store(0)
	unauthorized := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusUnauthorized)
	}))
	defer unauthorized.Close()
	if err := os.Setenv("BEBOP_TEST_WEBHOOK", unauthorized.URL); err != nil {
		t.Fatal(err)
	}
	result = sink.Deliver(context.Background(), events[0])
	if result.Delivered || result.Attempts != 1 || result.Category != "authentication" || requests.Load() != 1 {
		t.Fatalf("401 retry policy = %#v requests=%d", result, requests.Load())
	}
}

func TestWebhookEnforcesTLSAndRejectsRedirects(t *testing.T) {
	if _, err := validateWebhookURL("http://example.com/hook"); err == nil {
		t.Fatal("plaintext Internet webhook was accepted")
	}
	if _, err := validateWebhookURL("https://user:secret@example.com/hook"); err == nil {
		t.Fatal("userinfo webhook was accepted")
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "/elsewhere", http.StatusFound)
	}))
	defer redirect.Close()
	t.Setenv("BEBOP_TEST_WEBHOOK_REDIRECT", redirect.URL)
	sink := WebhookSink{urlEnv: "BEBOP_TEST_WEBHOOK_REDIRECT", client: newWebhookClient(), sleep: func(time.Duration) {}}
	result := sink.Deliver(context.Background(), testEvent(time.Now().UTC(), "doctor.failed", Error, "doctor", "failure"))
	if result.Delivered || result.Category != "redirect" || result.Attempts != 1 {
		t.Fatalf("redirect policy = %#v", result)
	}

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) { writer.WriteHeader(http.StatusNoContent) }))
	defer tlsServer.Close()
	t.Setenv("BEBOP_TEST_WEBHOOK_TLS", tlsServer.URL)
	result = (WebhookSink{urlEnv: "BEBOP_TEST_WEBHOOK_TLS", client: newWebhookClient(), sleep: func(time.Duration) {}}).Deliver(context.Background(), testEvent(time.Now().UTC(), "doctor.failed", Error, "doctor", "tls"))
	if result.Delivered || result.Category != "tls" || result.Attempts != 1 {
		t.Fatalf("TLS verification was not enforced: %#v", result)
	}
}
