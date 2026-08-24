package notification

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/bebop-home/bebop/internal/config"
)

// Sink delivers one already-sanitized event. Implementations must not mutate
// operational state and return categories rather than raw endpoint errors.
type Sink interface {
	Deliver(context.Context, Event) DeliveryOutcome
}

type DeliveryOutcome struct {
	Delivered  bool
	Attempts   int
	HTTPStatus int
	Category   string
}

// Service evaluates event policy synchronously at the end of an invocation.
// There is no queue, daemon, remote control plane, or retry worker.
type Service struct {
	policy config.Notifications
	store  Store
	sinks  map[string]Sink
	clock  func() time.Time
}

func NewService(cfg config.Config) (*Service, error) {
	if cfg.Notifications == nil {
		return nil, fmt.Errorf("notification configuration is not declared")
	}
	if err := config.ValidateNotifications(*cfg.Notifications); err != nil {
		return nil, err
	}
	store, err := OpenStore(cfg)
	if err != nil {
		return nil, err
	}
	service := &Service{policy: *cfg.Notifications, store: store, sinks: map[string]Sink{}, clock: time.Now}
	for _, definition := range service.policy.Sinks {
		sink, sinkErr := sinkFor(cfg, definition)
		if sinkErr != nil {
			return nil, sinkErr
		}
		service.sinks[definition.Name] = sink
	}
	return service, nil
}

func NewServiceForTest(policy config.Notifications, store Store, sinks map[string]Sink, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{policy: policy, store: store, sinks: sinks, clock: clock}
}

// Process records dedupe state and delivery history separately from the
// operation that produced events. A returned error is notification-only; the
// caller must not rewrite a successful operation as failed.
func (service *Service) Process(ctx context.Context, events []Event) ([]DeliveryResult, error) {
	if !service.policy.Enabled || len(events) == 0 {
		return nil, nil
	}
	filtered := make([]Event, 0, len(events))
	for _, event := range events {
		if event.Origin == "manual" && !service.policy.NotifyManual {
			continue
		}
		filtered = append(filtered, event)
	}
	if len(filtered) == 0 {
		return nil, nil
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].Fingerprint != filtered[j].Fingerprint {
			return filtered[i].Fingerprint < filtered[j].Fingerprint
		}
		return filtered[i].Type < filtered[j].Type
	})
	results := []DeliveryResult{}
	err := service.store.withLock(func(state *stateFile) error {
		for _, event := range filtered {
			if err := service.processEvent(ctx, state, event, &results); err != nil {
				return err
			}
		}
		return nil
	})
	return results, err
}

func (service *Service) processEvent(ctx context.Context, state *stateFile, event Event, results *[]DeliveryResult) error {
	if IsRecovery(event) {
		index := findIssue(state.Issues, event.Fingerprint)
		if index < 0 {
			return nil
		}
		issue := state.Issues[index]
		for _, route := range service.policy.Routes {
			if !routeMatches(route, event, true) {
				continue
			}
			if routeDelivery(issue, route.Name).Delivered {
				if err := service.deliver(ctx, route, event, results); err != nil {
					return err
				}
			}
		}
		state.Issues = append(state.Issues[:index], state.Issues[index+1:]...)
		return nil
	}
	if event.Severity == Info {
		for _, route := range service.policy.Routes {
			if routeMatches(route, event, false) {
				if err := service.deliver(ctx, route, event, results); err != nil {
					return err
				}
			}
		}
		return nil
	}
	index := findIssue(state.Issues, event.Fingerprint)
	if index < 0 {
		state.Issues = append(state.Issues, Issue{Fingerprint: event.Fingerprint, Type: event.Type, Severity: event.Severity, Target: event.Target, Job: event.Job, Service: event.Service, Resource: event.Resource, Summary: event.Summary, FirstSeen: event.OccurredAt, LastSeen: event.OccurredAt})
		index = len(state.Issues) - 1
	}
	issue := &state.Issues[index]
	escalated := SeverityRank(event.Severity) > SeverityRank(issue.Severity)
	issue.Type, issue.Severity, issue.LastSeen, issue.Summary = event.Type, event.Severity, event.OccurredAt, event.Summary
	for _, route := range service.policy.Routes {
		if !routeMatches(route, event, false) {
			continue
		}
		delivery := routeDelivery(*issue, route.Name)
		if delivery.Delivered && !escalated && !cooldownElapsed(route, delivery.LastNotified, event.OccurredAt) {
			result := DeliveryResult{SchemaVersion: DeliveryHistorySchemaVersion, EventID: event.EventID, Fingerprint: event.Fingerprint, Type: event.Type, Sink: route.Sink, Route: route.Name, AttemptedAt: event.OccurredAt, Result: "suppressed", Category: "already_active"}
			if err := service.store.appendDelivery(result); err != nil {
				return err
			}
			*results = append(*results, result)
			continue
		}
		result, err := service.deliverOne(ctx, route, event)
		if err != nil {
			return err
		}
		if result.Result == "delivered" {
			setRouteDelivery(issue, route.Name, true, event.OccurredAt)
		}
		*results = append(*results, result)
	}
	return nil
}

func (service *Service) deliver(ctx context.Context, route config.NotificationRoute, event Event, results *[]DeliveryResult) error {
	result, err := service.deliverOne(ctx, route, event)
	if err != nil {
		return err
	}
	*results = append(*results, result)
	return nil
}

func (service *Service) deliverOne(ctx context.Context, route config.NotificationRoute, event Event) (DeliveryResult, error) {
	sink, found := service.sinks[route.Sink]
	if !found {
		return DeliveryResult{}, fmt.Errorf("notification route %s sink %s is unavailable", route.Name, route.Sink)
	}
	outcome := sink.Deliver(ctx, event)
	result := DeliveryResult{SchemaVersion: DeliveryHistorySchemaVersion, EventID: event.EventID, Fingerprint: event.Fingerprint, Type: event.Type, Sink: route.Sink, Route: route.Name, AttemptedAt: event.OccurredAt, Attempts: outcome.Attempts, HTTPStatus: outcome.HTTPStatus, Category: outcome.Category, Test: event.Test}
	if outcome.Delivered {
		result.Result = "delivered"
	} else {
		result.Result = "failed"
	}
	if err := service.store.appendDelivery(result); err != nil {
		return DeliveryResult{}, err
	}
	return result, nil
}

// Test sends an explicitly synthetic event directly to one sink. It never
// loads or writes active issue state, so it cannot manufacture recovery noise.
func (service *Service) Test(ctx context.Context, sinkName string) (DeliveryResult, error) {
	sink, found := service.sinks[sinkName]
	if !found {
		return DeliveryResult{}, fmt.Errorf("unknown notification sink %q", sinkName)
	}
	now := service.clock().UTC()
	event := Event{SchemaVersion: EventSchemaVersion, EventID: eventID(now), Type: "maintenance.skipped", Severity: Info, OccurredAt: now, Fingerprint: IssueFingerprint("test", "controller", "test", "", "", "notification"), Origin: "manual", Target: "controller", Job: "test", Summary: "Bebop test notification", Details: Details{Category: "test"}, Test: true}
	outcome := sink.Deliver(ctx, event)
	result := DeliveryResult{SchemaVersion: DeliveryHistorySchemaVersion, EventID: event.EventID, Fingerprint: event.Fingerprint, Type: event.Type, Sink: sinkName, AttemptedAt: now, Attempts: outcome.Attempts, HTTPStatus: outcome.HTTPStatus, Category: outcome.Category, Test: true}
	if outcome.Delivered {
		result.Result = "delivered"
	} else {
		result.Result = "failed"
	}
	if err := service.store.appendDelivery(result); err != nil {
		return DeliveryResult{}, err
	}
	return result, nil
}

func findIssue(issues []Issue, fingerprint string) int {
	for index := range issues {
		if issues[index].Fingerprint == fingerprint {
			return index
		}
	}
	return -1
}

func routeDelivery(issue Issue, route string) RouteDelivery {
	for _, delivery := range issue.RouteDelivery {
		if delivery.Route == route {
			return delivery
		}
	}
	return RouteDelivery{Route: route}
}

func setRouteDelivery(issue *Issue, route string, delivered bool, when time.Time) {
	for index := range issue.RouteDelivery {
		if issue.RouteDelivery[index].Route == route {
			issue.RouteDelivery[index].Delivered, issue.RouteDelivery[index].LastNotified = delivered, when
			return
		}
	}
	issue.RouteDelivery = append(issue.RouteDelivery, RouteDelivery{Route: route, Delivered: delivered, LastNotified: when})
	sort.Slice(issue.RouteDelivery, func(i, j int) bool { return issue.RouteDelivery[i].Route < issue.RouteDelivery[j].Route })
}

func cooldownElapsed(route config.NotificationRoute, last, now time.Time) bool {
	if !last.IsZero() && route.Cooldown != "" {
		duration, err := time.ParseDuration(route.Cooldown)
		return err == nil && !now.Before(last.Add(duration))
	}
	return false
}

func routeMatches(route config.NotificationRoute, event Event, recovery bool) bool {
	if recovery && !route.Recoveries {
		return false
	}
	if !recovery && len(route.Severities) > 0 {
		found := false
		for _, severity := range route.Severities {
			if severity == string(event.Severity) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	for _, selected := range route.Events {
		if selected == event.Type {
			return true
		}
		if recovery && recoveryMatches(selected, event.Type) {
			return true
		}
	}
	return false
}

func recoveryMatches(selected, recovered string) bool {
	return (selected == "backup.failed" && recovered == "maintenance.recovered") ||
		(selected == "doctor.warning" && recovered == "doctor.recovered") ||
		(selected == "doctor.failed" && recovered == "doctor.recovered") ||
		(selected == "updates.available" && recovered == "updates.cleared") ||
		(selected == "maintenance.failed" && recovered == "maintenance.recovered") ||
		(selected == "storage.failed" && recovered == "storage.recovered") ||
		(selected == "service.unhealthy" && recovered == "service.recovered")
}
