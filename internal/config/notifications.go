package config

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

const NotificationsSchemaVersion = 1

// Notifications is controller-local M8 routing policy. It contains only
// secret references, never resolved webhook URLs or credentials.
type Notifications struct {
	Version           int                 `toml:"version" json:"version"`
	Enabled           bool                `toml:"enabled" json:"enabled"`
	NotifyManual      bool                `toml:"notify_manual" json:"notify_manual,omitempty"`
	StateDirectory    string              `toml:"state_dir" json:"state_dir"`
	HistoryMaxEntries int                 `toml:"history_max_entries" json:"history_max_entries"`
	Sinks             []NotificationSink  `toml:"-" json:"sinks"`
	Routes            []NotificationRoute `toml:"-" json:"routes"`
}

type NotificationSink struct {
	Name             string `toml:"name" json:"name"`
	Type             string `toml:"type" json:"type"`
	Path             string `toml:"path,omitempty" json:"path,omitempty"`
	URLEnv           string `toml:"url_env,omitempty" json:"url_env,omitempty"`
	AuthorizationEnv string `toml:"authorization_env,omitempty" json:"authorization_env,omitempty"`
}

type NotificationRoute struct {
	Name       string   `toml:"name" json:"name"`
	Sink       string   `toml:"sink" json:"sink"`
	Events     []string `toml:"events" json:"events"`
	Severities []string `toml:"severities,omitempty" json:"severities,omitempty"`
	Recoveries bool     `toml:"recoveries" json:"recoveries"`
	Cooldown   string   `toml:"cooldown,omitempty" json:"cooldown,omitempty"`
}

type rawNotifications struct {
	Version           *int                   `toml:"version"`
	Enabled           *bool                  `toml:"enabled"`
	NotifyManual      *bool                  `toml:"notify_manual"`
	StateDirectory    *string                `toml:"state_dir"`
	HistoryMaxEntries *int                   `toml:"history_max_entries"`
	Sinks             []rawNotificationSink  `toml:"sinks"`
	Routes            []rawNotificationRoute `toml:"routes"`
}

type rawNotificationSink struct {
	Name             *string `toml:"name"`
	Type             *string `toml:"type"`
	Path             *string `toml:"path"`
	URLEnv           *string `toml:"url_env"`
	AuthorizationEnv *string `toml:"authorization_env"`
}

type rawNotificationRoute struct {
	Name       *string  `toml:"name"`
	Sink       *string  `toml:"sink"`
	Events     []string `toml:"events"`
	Severities []string `toml:"severities"`
	Recoveries *bool    `toml:"recoveries"`
	Cooldown   *string  `toml:"cooldown"`
}

func decodeNotifications(raw rawNotifications) (Notifications, error) {
	result := Notifications{Enabled: true, StateDirectory: DefaultNotificationStateDirectory, HistoryMaxEntries: DefaultNotificationHistoryMaxEntries}
	if raw.Version != nil {
		result.Version = *raw.Version
	}
	if raw.Enabled != nil {
		result.Enabled = *raw.Enabled
	}
	if raw.NotifyManual != nil {
		result.NotifyManual = *raw.NotifyManual
	}
	if raw.StateDirectory != nil {
		result.StateDirectory = *raw.StateDirectory
	}
	if raw.HistoryMaxEntries != nil {
		result.HistoryMaxEntries = *raw.HistoryMaxEntries
	}
	for index, rawSink := range raw.Sinks {
		sink := NotificationSink{}
		if rawSink.Name != nil {
			sink.Name = *rawSink.Name
		}
		if rawSink.Type != nil {
			sink.Type = *rawSink.Type
		}
		if rawSink.Path != nil {
			sink.Path = *rawSink.Path
		}
		if rawSink.URLEnv != nil {
			sink.URLEnv = *rawSink.URLEnv
		}
		if rawSink.AuthorizationEnv != nil {
			sink.AuthorizationEnv = *rawSink.AuthorizationEnv
		}
		if sink.Name == "" {
			return Notifications{}, fmt.Errorf("notifications.sinks[%d].name is required", index)
		}
		result.Sinks = append(result.Sinks, sink)
	}
	for index, rawRoute := range raw.Routes {
		route := NotificationRoute{Recoveries: false}
		if rawRoute.Name != nil {
			route.Name = *rawRoute.Name
		}
		if rawRoute.Sink != nil {
			route.Sink = *rawRoute.Sink
		}
		route.Events = append([]string(nil), rawRoute.Events...)
		route.Severities = append([]string(nil), rawRoute.Severities...)
		if rawRoute.Recoveries != nil {
			route.Recoveries = *rawRoute.Recoveries
		}
		if rawRoute.Cooldown != nil {
			route.Cooldown = *rawRoute.Cooldown
		}
		if route.Name == "" {
			return Notifications{}, fmt.Errorf("notifications.routes[%d].name is required", index)
		}
		result.Routes = append(result.Routes, route)
	}
	sort.Slice(result.Sinks, func(i, j int) bool { return result.Sinks[i].Name < result.Sinks[j].Name })
	sort.Slice(result.Routes, func(i, j int) bool { return result.Routes[i].Name < result.Routes[j].Name })
	return result, nil
}

var notificationEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

var notificationEventTypes = map[string]bool{
	"backup.succeeded": true, "backup.failed": true, "backup.retention_failed": true,
	"doctor.warning": true, "doctor.failed": true, "doctor.recovered": true,
	"updates.available": true, "updates.cleared": true,
	"maintenance.failed": true, "maintenance.skipped": true, "maintenance.recovered": true,
	"storage.failed": true, "storage.recovered": true,
	"service.unhealthy": true, "service.recovered": true,
}

func NotificationEventTypes() []string {
	result := make([]string, 0, len(notificationEventTypes))
	for event := range notificationEventTypes {
		result = append(result, event)
	}
	sort.Strings(result)
	return result
}

func ValidateNotifications(notifications Notifications) error {
	if notifications.Version != NotificationsSchemaVersion {
		return fmt.Errorf("notifications.version must be %d", NotificationsSchemaVersion)
	}
	if err := ValidateControllerRelativePath(notifications.StateDirectory, false); err != nil {
		return fmt.Errorf("notifications.state_dir %w", err)
	}
	if notifications.StateDirectory == "." {
		return fmt.Errorf("notifications.state_dir must name a dedicated directory")
	}
	if notifications.HistoryMaxEntries < 1 || notifications.HistoryMaxEntries > 100_000 {
		return fmt.Errorf("notifications.history_max_entries must be between 1 and 100000")
	}
	sinks := map[string]bool{}
	for _, sink := range notifications.Sinks {
		if !serviceNamePattern.MatchString(sink.Name) {
			return fmt.Errorf("notification sink name must be a safe identifier")
		}
		if sinks[sink.Name] {
			return fmt.Errorf("notification sink names must be unique")
		}
		sinks[sink.Name] = true
		switch sink.Type {
		case "file":
			if err := ValidateControllerRelativePath(sink.Path, true); err != nil {
				return fmt.Errorf("notification sink %s path %w", sink.Name, err)
			}
			if sink.URLEnv != "" || sink.AuthorizationEnv != "" {
				return fmt.Errorf("notification file sink %s must not declare webhook settings", sink.Name)
			}
		case "webhook":
			if sink.Path != "" || !notificationEnvironmentName.MatchString(sink.URLEnv) {
				return fmt.Errorf("notification webhook sink %s requires a safe url_env and no path", sink.Name)
			}
			if sink.AuthorizationEnv != "" && !notificationEnvironmentName.MatchString(sink.AuthorizationEnv) {
				return fmt.Errorf("notification webhook sink %s authorization_env must be a safe environment variable name", sink.Name)
			}
		default:
			return fmt.Errorf("notification sink %s type must be file or webhook", sink.Name)
		}
	}
	routes := map[string]bool{}
	for _, route := range notifications.Routes {
		if !serviceNamePattern.MatchString(route.Name) {
			return fmt.Errorf("notification route name must be a safe identifier")
		}
		if routes[route.Name] {
			return fmt.Errorf("notification route names must be unique")
		}
		routes[route.Name] = true
		if !sinks[route.Sink] {
			return fmt.Errorf("notification route %s references unknown sink %s", route.Name, route.Sink)
		}
		if len(route.Events) == 0 {
			return fmt.Errorf("notification route %s requires at least one event", route.Name)
		}
		seenEvents := map[string]bool{}
		for _, event := range route.Events {
			if !notificationEventTypes[event] {
				return fmt.Errorf("notification route %s references unknown event %s", route.Name, event)
			}
			if seenEvents[event] {
				return fmt.Errorf("notification route %s repeats event %s", route.Name, event)
			}
			seenEvents[event] = true
		}
		seenSeverity := map[string]bool{}
		for _, severity := range route.Severities {
			if severity != "info" && severity != "warning" && severity != "error" && severity != "recovery" {
				return fmt.Errorf("notification route %s has unsupported severity %s", route.Name, severity)
			}
			if seenSeverity[severity] {
				return fmt.Errorf("notification route %s repeats severity %s", route.Name, severity)
			}
			seenSeverity[severity] = true
		}
		if route.Cooldown != "" {
			duration, err := time.ParseDuration(route.Cooldown)
			if err != nil || duration < time.Minute || duration > 30*24*time.Hour {
				return fmt.Errorf("notification route %s cooldown must be between 1m and 720h", route.Name)
			}
		}
		if !route.Recoveries {
			for _, event := range route.Events {
				if strings.HasSuffix(event, ".recovered") || event == "updates.cleared" {
					return fmt.Errorf("notification route %s selects recovery event %s but recoveries is false", route.Name, event)
				}
			}
		}
	}
	return nil
}
