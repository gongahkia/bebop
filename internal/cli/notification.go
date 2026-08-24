package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/notification"
)

func (r *Runner) notification(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("notification requires list, show, status, history, or test")
	}
	switch arguments[0] {
	case "list":
		return r.notificationList(arguments[1:])
	case "show":
		return r.notificationShow(arguments[1:])
	case "status":
		return r.notificationStatus(arguments[1:])
	case "history":
		return r.notificationHistory(arguments[1:])
	case "test":
		return r.notificationTest(arguments[1:])
	default:
		return fmt.Errorf("unknown notification command %q", arguments[0])
	}
}

func notificationConfig(filename string) (config.Config, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return config.Config{}, err
	}
	cfg, err := config.LoadFile(abs)
	if err != nil {
		return config.Config{}, err
	}
	if cfg.Notifications == nil {
		return config.Config{}, fmt.Errorf("notification configuration is not declared in %s", abs)
	}
	return cfg, nil
}

func (r *Runner) notificationList(arguments []string) error {
	fs := newNotificationFlags(r, "notification list")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("notification list accepts no positional arguments")
	}
	cfg, err := notificationConfig(fs.Lookup("config").Value.String())
	if err != nil {
		return err
	}
	if fs.Lookup("json").Value.String() == "true" {
		return writeJSON(r.Out, struct {
			SchemaVersion int                        `json:"schema_version"`
			Enabled       bool                       `json:"enabled"`
			Sinks         []config.NotificationSink  `json:"sinks"`
			Routes        []config.NotificationRoute `json:"routes"`
		}{cfg.Notifications.Version, cfg.Notifications.Enabled, cfg.Notifications.Sinks, cfg.Notifications.Routes})
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "SINK\tTYPE\tCONFIGURATION")
	for _, sink := range cfg.Notifications.Sinks {
		configuration := sink.Path
		if sink.Type == "webhook" {
			configuration = "env:" + sink.URLEnv
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\n", sink.Name, sink.Type, configuration)
	}
	fmt.Fprintln(writer, "\nROUTE\tSINK\tEVENTS\tCOOLDOWN\tRECOVERIES")
	for _, route := range cfg.Notifications.Routes {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%t\n", route.Name, route.Sink, joinValues(route.Events), nonEmptyText(route.Cooldown, "-"), route.Recoveries)
	}
	return writer.Flush()
}

func (r *Runner) notificationShow(arguments []string) error {
	fs := newNotificationFlags(r, "notification show")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("notification show requires exactly one sink or route name")
	}
	cfg, err := notificationConfig(fs.Lookup("config").Value.String())
	if err != nil {
		return err
	}
	name := fs.Arg(0)
	for _, sink := range cfg.Notifications.Sinks {
		if sink.Name != name {
			continue
		}
		if fs.Lookup("json").Value.String() == "true" {
			return writeJSON(r.Out, sink)
		}
		fmt.Fprintf(r.Out, "Sink     %s\nType     %s\n", sink.Name, sink.Type)
		if sink.Type == "file" {
			fmt.Fprintf(r.Out, "Path     %s\n", sink.Path)
		} else {
			fmt.Fprintf(r.Out, "URL env  %s\n", sink.URLEnv)
			if sink.AuthorizationEnv != "" {
				fmt.Fprintf(r.Out, "Auth env %s\n", sink.AuthorizationEnv)
			}
		}
		return nil
	}
	for _, route := range cfg.Notifications.Routes {
		if route.Name != name {
			continue
		}
		if fs.Lookup("json").Value.String() == "true" {
			return writeJSON(r.Out, route)
		}
		fmt.Fprintf(r.Out, "Route      %s\nSink       %s\nEvents     %s\nRecoveries %t\nCooldown   %s\n", route.Name, route.Sink, joinValues(route.Events), route.Recoveries, nonEmptyText(route.Cooldown, "none"))
		return nil
	}
	return fmt.Errorf("unknown notification sink or route %q", name)
}

func (r *Runner) notificationStatus(arguments []string) error {
	fs := newNotificationFlags(r, "notification status")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("notification status accepts no positional arguments")
	}
	cfg, err := notificationConfig(fs.Lookup("config").Value.String())
	if err != nil {
		return err
	}
	store, err := notification.ExistingStore(cfg)
	if err != nil {
		return err
	}
	issues, err := store.ActiveIssues()
	if err != nil {
		return err
	}
	response := struct {
		Enabled      bool                     `json:"enabled"`
		ActiveIssues []notification.Issue     `json:"active_issues"`
		Sinks        []notificationSinkStatus `json:"sinks"`
	}{Enabled: cfg.Notifications.Enabled, ActiveIssues: issues}
	for _, sink := range cfg.Notifications.Sinks {
		status := notificationSinkStatus{Name: sink.Name, Type: sink.Type, Status: "configured"}
		if sink.Type == "webhook" {
			if _, found := os.LookupEnv(sink.URLEnv); !found {
				status.Status = "secret-unavailable"
			}
		}
		response.Sinks = append(response.Sinks, status)
	}
	if fs.Lookup("json").Value.String() == "true" {
		return writeJSON(r.Out, response)
	}
	fmt.Fprintf(r.Out, "Notifications: %t\n", response.Enabled)
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "SINK\tTYPE\tSTATUS")
	for _, sink := range response.Sinks {
		fmt.Fprintf(writer, "%s\t%s\t%s\n", sink.Name, sink.Type, sink.Status)
	}
	fmt.Fprintln(writer, "\nACTIVE ISSUE\tTARGET\tSINCE\tLAST NOTIFIED")
	for _, issue := range issues {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", issue.Type, issue.Target, issue.FirstSeen.Local().Format("2006-01-02 15:04"), latestNotification(issue).Local().Format("2006-01-02 15:04"))
	}
	return writer.Flush()
}

type notificationSinkStatus struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

func (r *Runner) notificationHistory(arguments []string) error {
	fs := newNotificationFlags(r, "notification history")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("notification history accepts no positional arguments")
	}
	cfg, err := notificationConfig(fs.Lookup("config").Value.String())
	if err != nil {
		return err
	}
	store, err := notification.ExistingStore(cfg)
	if err != nil {
		return err
	}
	history, err := store.DeliveryHistory()
	if err != nil {
		return err
	}
	if fs.Lookup("json").Value.String() == "true" {
		return writeJSON(r.Out, struct {
			Deliveries []notification.DeliveryResult `json:"deliveries"`
		}{history})
	}
	if len(history) == 0 {
		fmt.Fprintln(r.Out, "No notification delivery history recorded.")
		return nil
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "TIME\tEVENT\tSINK\tRESULT\tATTEMPTS")
	for _, delivery := range history {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d\n", delivery.AttemptedAt.Local().Format("2006-01-02 15:04:05"), delivery.Type, delivery.Sink, delivery.Result, delivery.Attempts)
	}
	return writer.Flush()
}

func (r *Runner) notificationTest(arguments []string) error {
	fs := newNotificationFlags(r, "notification test")
	timeout := fs.Duration("timeout", 15*time.Second, "maximum notification delivery duration")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("notification test requires exactly one sink name")
	}
	cfg, err := notificationConfig(fs.Lookup("config").Value.String())
	if err != nil {
		return err
	}
	service, err := notification.NewService(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	result, testErr := service.Test(ctx, fs.Arg(0))
	if fs.Lookup("json").Value.String() == "true" {
		if err := writeJSON(r.Out, result); err != nil {
			return err
		}
	} else if result.Result == "delivered" {
		fmt.Fprintf(r.Out, "Test notification delivered to %s.\n", result.Sink)
	} else {
		fmt.Fprintf(r.Out, "Test notification failed for %s (%s).\n", result.Sink, nonEmptyText(result.Category, "unavailable"))
	}
	return testErr
}

func newNotificationFlags(r *Runner, name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(r.Err)
	fs.String("config", "bebop.toml", "path to notification bebop.toml")
	fs.Bool("json", false, "write machine-readable JSON")
	return fs
}

func joinValues(values []string) string { return strings.Join(values, ",") }
func nonEmptyText(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
func latestNotification(issue notification.Issue) time.Time {
	latest := time.Time{}
	for _, delivery := range issue.RouteDelivery {
		if delivery.LastNotified.After(latest) {
			latest = delivery.LastNotified
		}
	}
	return latest
}
