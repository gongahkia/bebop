package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/maintenance"
	"github.com/bebop-home/bebop/internal/notification"
)

func (r *Runner) maintenance(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("maintenance requires list, show, run, install, uninstall, status, or history")
	}
	switch arguments[0] {
	case "list":
		return r.maintenanceList(arguments[1:])
	case "show":
		return r.maintenanceShow(arguments[1:])
	case "run":
		return r.maintenanceRun(arguments[1:])
	case "install":
		return r.maintenanceInstall(arguments[1:])
	case "uninstall":
		return r.maintenanceUninstall(arguments[1:])
	case "status":
		return r.maintenanceStatus(arguments[1:])
	case "history":
		return r.maintenanceHistory(arguments[1:])
	default:
		return fmt.Errorf("unknown maintenance command %q", arguments[0])
	}
}

// maintenanceConfig loads the policy from a real file, which is required for
// controller-relative history and stable scheduler project binding.
func maintenanceConfig(filename string) (config.Config, string, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return config.Config{}, "", err
	}
	cfg, err := config.LoadFile(abs)
	if err != nil {
		return config.Config{}, "", err
	}
	if cfg.Maintenance == nil {
		return config.Config{}, "", fmt.Errorf("maintenance configuration is not declared in %s", abs)
	}
	return cfg, abs, nil
}

func (r *Runner) maintenanceList(arguments []string) error {
	fs := flag.NewFlagSet("maintenance list", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("maintenance list accepts no positional arguments")
	}
	cfg, _, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			SchemaVersion int                     `json:"schema_version"`
			Jobs          []config.MaintenanceJob `json:"jobs"`
		}{SchemaVersion: cfg.Maintenance.Version, Jobs: cfg.Maintenance.Jobs})
	}
	if len(cfg.Maintenance.Jobs) == 0 {
		fmt.Fprintln(r.Out, "No maintenance jobs declared.")
		return nil
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tTYPE\tTARGET\tSCHEDULE\tENABLED")
	for _, job := range cfg.Maintenance.Jobs {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%t\n", job.Name, job.Type, job.Target, job.Schedule.String(), job.Enabled)
	}
	return writer.Flush()
}

func (r *Runner) maintenanceShow(arguments []string) error {
	fs := flag.NewFlagSet("maintenance show", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	inventoryPath := fs.String("inventory", inventory.DefaultPath, "path to host inventory")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("maintenance show requires exactly one job name")
	}
	cfg, absoluteConfig, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	job, found := maintenanceJob(cfg.Maintenance.Jobs, fs.Arg(0))
	if !found {
		return fmt.Errorf("unknown maintenance job %q", fs.Arg(0))
	}
	fingerprint, err := job.Fingerprint()
	if err != nil {
		return err
	}
	history, err := maintenance.ExistingHistory(cfg)
	if err != nil {
		return err
	}
	records, err := history.List(job.Name)
	if err != nil {
		return err
	}
	scheduler, schedulerErr := maintenance.NewScheduler(absoluteConfig, *inventoryPath)
	schedulerState := "unavailable"
	schedulerDetail := ""
	if schedulerErr == nil {
		capability, detail := scheduler.Capability(context.Background())
		schedulerDetail = detail
		if capability == maintenance.SchedulerAvailable {
			statuses, statusErr := scheduler.Status(context.Background(), []config.MaintenanceJob{job})
			if statusErr == nil && len(statuses) == 1 {
				schedulerState = statuses[0].State
				schedulerDetail = statuses[0].Detail
			} else if statusErr != nil {
				schedulerState = "unit-error"
				schedulerDetail = statusErr.Error()
			}
		} else {
			schedulerState = string(capability)
		}
	} else {
		schedulerDetail = schedulerErr.Error()
	}
	var last *maintenance.Record
	if len(records) > 0 {
		last = &records[0]
	}
	response := struct {
		Job              config.MaintenanceJob `json:"job"`
		Fingerprint      string                `json:"fingerprint"`
		SchedulerBackend string                `json:"scheduler_backend,omitempty"`
		SchedulerState   string                `json:"scheduler_state"`
		SchedulerDetail  string                `json:"scheduler_detail,omitempty"`
		LastRun          *maintenance.Record   `json:"last_run,omitempty"`
	}{Job: job, Fingerprint: fingerprint, SchedulerBackend: schedulerBackend(scheduler), SchedulerState: schedulerState, SchedulerDetail: schedulerDetail, LastRun: last}
	if *jsonOutput {
		return writeJSON(r.Out, response)
	}
	fmt.Fprintf(r.Out, "Job            %s\nType           %s\nTarget         %s\nSchedule       %s (controller local time)\nEnabled        %t\nFingerprint    %s\nScheduler      %s (%s)\n", job.Name, job.Type, job.Target, job.Schedule.String(), job.Enabled, fingerprint, schedulerBackend(scheduler), schedulerState)
	if job.Service != "" {
		fmt.Fprintf(r.Out, "Service        %s\n", job.Service)
	}
	if job.Window != nil {
		fmt.Fprintf(r.Out, "Window         %s-%s\n", job.Window.Start, job.Window.End)
	}
	if job.Retention.KeepLast > 0 {
		fmt.Fprintf(r.Out, "Retention      keep_last=%d (maintenance snapshots only)\n", job.Retention.KeepLast)
	}
	if job.RefreshMetadata {
		fmt.Fprintln(r.Out, "Update metadata refresh enabled")
	}
	if schedulerDetail != "" {
		fmt.Fprintf(r.Out, "Scheduler info %s\n", schedulerDetail)
	}
	if last != nil {
		fmt.Fprintf(r.Out, "Last run       %s  %s\n", last.StartedAt.Local().Format("2006-01-02 15:04:05 MST"), last.Result)
	}
	return nil
}

func (r *Runner) maintenanceRun(arguments []string) error {
	fs := flag.NewFlagSet("maintenance run", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	inventoryPath := fs.String("inventory", inventory.DefaultPath, "path to host inventory")
	timeout := fs.Duration("timeout", 15*time.Minute, "maximum maintenance operation duration")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	ignoreWindow := fs.Bool("ignore-window", false, "explicitly run a manual job outside its configured window")
	scheduled := fs.Bool("scheduled", false, "internal marker used by generated scheduler artifacts")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("maintenance run requires exactly one job name")
	}
	cfg, _, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	history, err := maintenance.NewHistory(cfg)
	if err != nil {
		return err
	}
	locksDirectory := filepath.Join(cfg.SourceDirectory(), ".bebop", "maintenance", "locks")
	executor := maintenance.BebopExecutor{Service: r.Service, PolicyConfig: cfg, InventoryPath: *inventoryPath, OperationTimeout: *timeout}
	runner := maintenance.Runner{Jobs: cfg.Maintenance.Jobs, History: history, Locks: maintenance.LocalLocker{Directory: locksDirectory}, Executor: executor}
	notificationSetupError := ""
	if cfg.Notifications != nil && cfg.Notifications.Enabled {
		processor, processorErr := notification.NewService(cfg)
		if processorErr != nil {
			notificationSetupError = "notification delivery unavailable"
		} else {
			runner.Notifier = processor
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	origin := "manual"
	if *scheduled {
		origin = "scheduled"
	}
	invocation, runErr := runner.RunDetailed(ctx, fs.Arg(0), maintenance.RunOptions{Origin: origin, IgnoreWindow: *ignoreWindow})
	if notificationSetupError != "" && invocation.NotificationError == "" {
		invocation.NotificationError = notificationSetupError
	}
	if *jsonOutput {
		if cfg.Notifications == nil || !cfg.Notifications.Enabled {
			if err := writeJSON(r.Out, invocation.Record); err != nil {
				return err
			}
		} else if err := writeJSON(r.Out, invocation); err != nil {
			return err
		}
	} else {
		renderMaintenanceRecord(r.Out, invocation.Record)
		renderNotificationSummary(r.Out, invocation)
	}
	return runErr
}

func renderNotificationSummary(output io.Writer, invocation maintenance.InvocationResult) {
	if len(invocation.Notifications) == 0 && invocation.NotificationError == "" {
		return
	}
	delivered, failed, suppressed := 0, 0, 0
	for _, result := range invocation.Notifications {
		switch result.Result {
		case "delivered":
			delivered++
		case "failed":
			failed++
		case "suppressed":
			suppressed++
		}
	}
	if delivered > 0 || suppressed > 0 {
		fmt.Fprintf(output, "Notifications: delivered=%d suppressed=%d\n", delivered, suppressed)
	}
	if failed > 0 || invocation.NotificationError != "" {
		fmt.Fprintln(output, "Notification: unavailable; underlying maintenance result is unchanged")
	}
}

func (r *Runner) maintenanceInstall(arguments []string) error {
	fs := flag.NewFlagSet("maintenance install", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	inventoryPath := fs.String("inventory", inventory.DefaultPath, "path to host inventory")
	dryRun := fs.Bool("dry-run", false, "show scheduler changes without writing controller scheduler artifacts")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("maintenance install accepts no positional arguments")
	}
	cfg, absoluteConfig, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	scheduler, err := maintenance.NewScheduler(absoluteConfig, *inventoryPath)
	if err != nil {
		return err
	}
	changes, err := scheduler.Install(context.Background(), cfg.Maintenance.Jobs, *dryRun)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Backend string                   `json:"backend"`
			DryRun  bool                     `json:"dry_run"`
			Changes []maintenance.UnitChange `json:"changes"`
		}{Backend: scheduler.Backend(), DryRun: *dryRun, Changes: changes})
	}
	if len(changes) == 0 {
		fmt.Fprintln(r.Out, "Maintenance scheduler artifacts are current.")
		return nil
	}
	for _, change := range changes {
		fmt.Fprintf(r.Out, "%s %s\n", maintenanceChangeMarker(change.Action), change.Unit)
	}
	if *dryRun {
		fmt.Fprintln(r.Out, "No scheduler artifacts were changed.")
	} else {
		fmt.Fprintln(r.Out, "Maintenance scheduler artifacts installed.")
	}
	return nil
}

func (r *Runner) maintenanceUninstall(arguments []string) error {
	fs := flag.NewFlagSet("maintenance uninstall", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	inventoryPath := fs.String("inventory", inventory.DefaultPath, "path to host inventory")
	yes := fs.Bool("yes", false, "remove only Bebop-owned controller scheduler artifacts")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("maintenance uninstall accepts no positional arguments")
	}
	if !*yes {
		return fmt.Errorf("maintenance uninstall removes only Bebop-owned controller scheduler artifacts; repeat with --yes to confirm")
	}
	cfg, absoluteConfig, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	scheduler, err := maintenance.NewScheduler(absoluteConfig, *inventoryPath)
	if err != nil {
		return err
	}
	changes, err := scheduler.Uninstall(context.Background(), cfg.Maintenance.Jobs)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Backend string                   `json:"backend"`
			Changes []maintenance.UnitChange `json:"changes"`
		}{Backend: scheduler.Backend(), Changes: changes})
	}
	if len(changes) == 0 {
		fmt.Fprintln(r.Out, "No Bebop-owned maintenance scheduler artifacts were installed.")
		return nil
	}
	for _, change := range changes {
		fmt.Fprintf(r.Out, "- %s\n", change.Unit)
	}
	fmt.Fprintln(r.Out, "Maintenance scheduler artifacts removed; policy, history, and backups were preserved.")
	return nil
}

func (r *Runner) maintenanceStatus(arguments []string) error {
	fs := flag.NewFlagSet("maintenance status", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	inventoryPath := fs.String("inventory", inventory.DefaultPath, "path to host inventory")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("maintenance status accepts no positional arguments")
	}
	cfg, absoluteConfig, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	scheduler, err := maintenance.NewScheduler(absoluteConfig, *inventoryPath)
	if err != nil {
		return err
	}
	capability, detail := scheduler.Capability(context.Background())
	if capability != maintenance.SchedulerAvailable {
		if *jsonOutput {
			return writeJSON(r.Out, struct {
				Backend    string                          `json:"backend"`
				Capability maintenance.SchedulerCapability `json:"capability"`
				Detail     string                          `json:"detail"`
			}{scheduler.Backend(), capability, detail})
		}
		fmt.Fprintf(r.Out, "Scheduler: %s (%s)\n", capability, detail)
		return nil
	}
	statuses, err := scheduler.Status(context.Background(), cfg.Maintenance.Jobs)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Backend    string                           `json:"backend"`
			Capability maintenance.SchedulerCapability  `json:"capability"`
			Jobs       []maintenance.SchedulerJobStatus `json:"jobs"`
		}{scheduler.Backend(), capability, statuses})
	}
	history, historyErr := maintenance.ExistingHistory(cfg)
	last := map[string]maintenance.Record{}
	if historyErr == nil {
		if records, listErr := history.List(""); listErr == nil {
			for _, record := range records {
				if _, exists := last[record.Job]; !exists {
					last[record.Job] = record
				}
			}
		}
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintf(writer, "Scheduler backend: %s\n", scheduler.Backend())
	fmt.Fprintln(writer, "JOB\tSCHEDULE\tSCHEDULER\tLAST RUN\tRESULT")
	for _, status := range statuses {
		job, _ := maintenanceJob(cfg.Maintenance.Jobs, status.Job)
		lastRun, result := "-", "-"
		if record, exists := last[status.Job]; exists {
			lastRun, result = record.StartedAt.Local().Format("2006-01-02 15:04"), string(record.Result)
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", status.Job, job.Schedule.String(), status.State, lastRun, result)
	}
	return writer.Flush()
}

func (r *Runner) maintenanceHistory(arguments []string) error {
	fs := flag.NewFlagSet("maintenance history", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to maintenance bebop.toml")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return fmt.Errorf("maintenance history accepts at most one job name")
	}
	cfg, _, err := maintenanceConfig(*configPath)
	if err != nil {
		return err
	}
	job := ""
	if fs.NArg() == 1 {
		job = fs.Arg(0)
		if _, found := maintenanceJob(cfg.Maintenance.Jobs, job); !found {
			return fmt.Errorf("unknown maintenance job %q", job)
		}
	}
	history, err := maintenance.ExistingHistory(cfg)
	if err != nil {
		return err
	}
	records, err := history.List(job)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Records []maintenance.Record `json:"records"`
		}{records})
	}
	if len(records) == 0 {
		fmt.Fprintln(r.Out, "No maintenance history recorded.")
		return nil
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "TIME\tJOB\tRESULT\tDETAILS")
	for _, record := range records {
		details := record.Details.Reason
		if record.Details.SnapshotID != "" {
			details = "snapshot " + record.Details.SnapshotID
		}
		if record.Error != "" {
			details = record.Error
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", record.StartedAt.Local().Format("2006-01-02 15:04:05"), record.Job, record.Result, details)
	}
	return writer.Flush()
}

func maintenanceJob(jobs []config.MaintenanceJob, name string) (config.MaintenanceJob, bool) {
	for _, job := range jobs {
		if job.Name == name {
			return job, true
		}
	}
	return config.MaintenanceJob{}, false
}

func schedulerBackend(scheduler maintenance.SchedulerAdapter) string {
	if scheduler == nil {
		return "unavailable"
	}
	return scheduler.Backend()
}

func maintenanceChangeMarker(action string) string {
	switch action {
	case "install":
		return "+"
	case "update":
		return "~"
	default:
		return "-"
	}
}

func renderMaintenanceRecord(output io.Writer, record maintenance.Record) {
	fmt.Fprintf(output, "Maintenance job: %s\nResult: %s\nRun: %s\n", record.Job, record.Result, record.RunID)
	if record.Details.Reason != "" {
		fmt.Fprintf(output, "Reason: %s\n", record.Details.Reason)
	}
	if record.Details.SnapshotID != "" {
		fmt.Fprintf(output, "Snapshot: %s\n", record.Details.SnapshotID)
	}
	if len(record.Details.RetentionDeleted) > 0 {
		fmt.Fprintf(output, "Retention deleted: %s\n", strings.Join(record.Details.RetentionDeleted, ", "))
	}
	if record.Details.UpdatesAvailable > 0 || record.Operation == "update-check" {
		fmt.Fprintf(output, "Updates available: %d (security: %s)\n", record.Details.UpdatesAvailable, updateSecurityDetail(record.Details))
	}
	if record.Error != "" {
		fmt.Fprintf(output, "Error: %s\n", record.Error)
	}
}

func updateSecurityDetail(details maintenance.Details) string {
	if details.SecurityClassification == "known" {
		return fmt.Sprintf("%d", details.SecurityUpdates)
	}
	return "unknown"
}
