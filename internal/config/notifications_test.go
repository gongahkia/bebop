package config

import (
	"strings"
	"testing"
)

func TestNotificationsAreStrictAndOutsideTargetFingerprint(t *testing.T) {
	valid := `version = 1
[notifications]
version = 1
enabled = true
state_dir = ".bebop/notifications"
history_max_entries = 10

[[notifications.sinks]]
name = "events"
type = "file"
path = ".bebop/notifications/events.jsonl"

[[notifications.sinks]]
name = "ops"
type = "webhook"
url_env = "BEBOP_OPS_WEBHOOK_URL"
authorization_env = "BEBOP_OPS_AUTHORIZATION"

[[notifications.routes]]
name = "failures"
sink = "ops"
events = ["backup.failed", "doctor.failed"]
recoveries = true
cooldown = "1h"
`
	cfg, err := Decode(strings.NewReader(valid))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Notifications == nil || len(cfg.Notifications.Sinks) != 2 || cfg.Notifications.Routes[0].Name != "failures" {
		t.Fatalf("notifications were not decoded deterministically: %#v", cfg.Notifications)
	}
	before, err := Fingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Notifications.Routes[0].Cooldown = "2h"
	after, err := Fingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("controller notification policy changed target config fingerprint: %s != %s", before, after)
	}
	for _, malformed := range []string{
		strings.Replace(valid, `type = "webhook"`, `type = "command"`, 1),
		strings.Replace(valid, `url_env = "BEBOP_OPS_WEBHOOK_URL"`, `url = "https://secret.example"`, 1),
		strings.Replace(valid, `"backup.failed", "doctor.failed"`, `"backup.unknown"`, 1),
		strings.Replace(valid, `state_dir = ".bebop/notifications"`, `state_dir = "../notifications"`, 1),
		strings.Replace(valid, `cooldown = "1h"`, `cooldown = "1x"`, 1),
	} {
		if _, err := Decode(strings.NewReader(malformed)); err == nil {
			t.Fatalf("invalid notification policy was accepted:\n%s", malformed)
		}
	}
}
