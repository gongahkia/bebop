package notification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/lease"
)

const webhookTimeout = 5 * time.Second

func sinkFor(cfg config.Config, definition config.NotificationSink) (Sink, error) {
	switch definition.Type {
	case "file":
		path, err := localPath(cfg.SourceDirectory(), definition.Path)
		if err != nil {
			return nil, err
		}
		return FileSink{path: path, base: cfg.SourceDirectory(), relative: definition.Path}, nil
	case "webhook":
		return WebhookSink{urlEnv: definition.URLEnv, authorizationEnv: definition.AuthorizationEnv, client: newWebhookClient(), sleep: time.Sleep}, nil
	default:
		return nil, fmt.Errorf("unsupported notification sink type %q", definition.Type)
	}
}

// FileSink emits self-contained versioned event JSON lines under the project
// tree. The sink is append-only and never overwrites user-authored files.
type FileSink struct {
	path     string
	base     string
	relative string
}

func (sink FileSink) Deliver(_ context.Context, event Event) DeliveryOutcome {
	if err := ensureSafeDirectory(sink.base, filepath.Dir(filepath.FromSlash(sink.relative))); err != nil {
		return DeliveryOutcome{Category: "unsafe_path", Attempts: 1}
	}
	info, err := os.Lstat(sink.path)
	if err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return DeliveryOutcome{Category: "unsafe_path", Attempts: 1}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return DeliveryOutcome{Category: "file_error", Attempts: 1}
	}
	encoded, err := json.Marshal(struct {
		SchemaVersion int   `json:"schema_version"`
		Event         Event `json:"event"`
	}{SchemaVersion: EventSchemaVersion, Event: event})
	if err != nil {
		return DeliveryOutcome{Category: "encode", Attempts: 1}
	}
	lock, err := lease.AcquireBlocking(sink.path + ".lock")
	if err != nil {
		return DeliveryOutcome{Category: "file_lock", Attempts: 1}
	}
	defer lock.Release()
	file, err := os.OpenFile(sink.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return DeliveryOutcome{Category: "file_error", Attempts: 1}
	}
	_, writeErr := file.Write(append(encoded, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return DeliveryOutcome{Category: "file_error", Attempts: 1}
	}
	return DeliveryOutcome{Delivered: true, Attempts: 1}
}

type WebhookSink struct {
	urlEnv           string
	authorizationEnv string
	client           *http.Client
	sleep            func(time.Duration)
}

func newWebhookClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	return &http.Client{Transport: transport, Timeout: webhookTimeout, CheckRedirect: func(request *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
}

func (sink WebhookSink) Deliver(ctx context.Context, event Event) DeliveryOutcome {
	endpoint, found := os.LookupEnv(sink.urlEnv)
	if !found || endpoint == "" {
		return DeliveryOutcome{Attempts: 1, Category: "secret_unavailable"}
	}
	parsed, err := validateWebhookURL(endpoint)
	if err != nil {
		return DeliveryOutcome{Attempts: 1, Category: "invalid_endpoint"}
	}
	authorization := ""
	if sink.authorizationEnv != "" {
		var authorized bool
		authorization, authorized = os.LookupEnv(sink.authorizationEnv)
		if !authorized || authorization == "" {
			return DeliveryOutcome{Attempts: 1, Category: "secret_unavailable"}
		}
	}
	client := sink.client
	if client == nil {
		client = newWebhookClient()
	}
	sleep := sink.sleep
	if sleep == nil {
		sleep = time.Sleep
	}
	payload, err := json.Marshal(struct {
		SchemaVersion int   `json:"schema_version"`
		Event         Event `json:"event"`
	}{SchemaVersion: EventSchemaVersion, Event: event})
	if err != nil {
		return DeliveryOutcome{Attempts: 1, Category: "encode"}
	}
	for attempt, delay := range []time.Duration{0, 100 * time.Millisecond, 250 * time.Millisecond} {
		if delay > 0 {
			sleep(delay)
		}
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, parsed.String(), bytes.NewReader(payload))
		if requestErr != nil {
			return DeliveryOutcome{Attempts: attempt + 1, Category: "invalid_endpoint"}
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("User-Agent", "bebop-notification/1")
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
			_ = response.Body.Close()
			if response.StatusCode >= 200 && response.StatusCode < 300 {
				return DeliveryOutcome{Delivered: true, Attempts: attempt + 1, HTTPStatus: response.StatusCode}
			}
			category, retry := httpFailure(response.StatusCode)
			if !retry || attempt == 2 {
				return DeliveryOutcome{Attempts: attempt + 1, HTTPStatus: response.StatusCode, Category: category}
			}
			continue
		}
		category, retry := requestFailure(requestErr)
		if !retry || attempt == 2 {
			return DeliveryOutcome{Attempts: attempt + 1, Category: category}
		}
	}
	return DeliveryOutcome{Attempts: 3, Category: "server_error"}
}

func validateWebhookURL(value string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return nil, fmt.Errorf("invalid webhook endpoint")
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "::1") {
		return parsed, nil
	}
	return nil, fmt.Errorf("webhook endpoint must use HTTPS")
}

func httpFailure(status int) (string, bool) {
	switch status {
	case http.StatusTooManyRequests:
		return "rate_limited", true
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return "server_error", true
	case http.StatusUnauthorized, http.StatusForbidden:
		return "authentication", false
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return "redirect", false
	default:
		if status >= 500 {
			return "server_error", false
		}
		return "invalid_request", false
	}
}

func requestFailure(err error) (string, bool) {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout", true
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return "timeout", true
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && strings.Contains(strings.ToLower(urlErr.Err.Error()), "tls") {
		return "tls", false
	}
	return "connection", true
}
