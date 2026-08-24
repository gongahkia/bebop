package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
)

const unitHeader = "# Managed by Bebop. Do not edit; run bebop maintenance install.\n"

type SchedulerCapability string

const (
	SchedulerAvailable   SchedulerCapability = "available"
	SchedulerUnsupported SchedulerCapability = "unsupported"
	SchedulerUnavailable SchedulerCapability = "unavailable"
)

type SystemdStatus = SchedulerJobStatus

type commandRunner func(context.Context, string, ...string) (string, error)

// SystemdUser is the Linux M7 scheduler adapter. It owns only controller user
// unit files; target scheduler state is intentionally never touched.
type SystemdUser struct {
	UnitDirectory string
	ProjectRoot   string
	ConfigPath    string
	InventoryPath string
	Executable    string
	Platform      string
	Systemctl     string
	run           commandRunner
}

func NewSystemdUser(configPath, inventoryPath string) (SystemdUser, error) {
	install, err := NewSchedulerContext(configPath, inventoryPath)
	if err != nil {
		return SystemdUser{}, err
	}
	return NewSystemdUserWithContext(install)
}

func NewSystemdUserWithContext(install SchedulerContext) (SystemdUser, error) {
	userConfig, err := os.UserConfigDir()
	if err != nil {
		return SystemdUser{}, fmt.Errorf("resolve controller user configuration directory: %w", err)
	}
	return SystemdUser{UnitDirectory: filepath.Join(userConfig, "systemd", "user"), ProjectRoot: install.ProjectRoot, ConfigPath: install.ConfigPath, InventoryPath: install.InventoryPath, Executable: install.Executable, Platform: install.Platform, Systemctl: "systemctl", run: runCommand}, nil
}

func (scheduler SystemdUser) Backend() string { return "systemd-user" }

func (scheduler SystemdUser) Capability(ctx context.Context) (SchedulerCapability, string) {
	if scheduler.Platform == "" {
		scheduler.Platform = runtime.GOOS
	}
	if scheduler.Platform != "linux" {
		return SchedulerUnsupported, "M7 scheduler installation currently supports Linux systemd user timers only"
	}
	program := scheduler.Systemctl
	if program == "" {
		program = "systemctl"
	}
	runner := scheduler.run
	if runner == nil {
		if _, err := exec.LookPath(program); err != nil {
			return SchedulerUnavailable, "systemctl is not available on this controller"
		}
		runner = runCommand
	}
	if _, err := runner(ctx, program, "--user", "show-environment"); err != nil {
		return SchedulerUnavailable, "systemd user manager is unavailable: " + conciseError(err)
	}
	return SchedulerAvailable, "systemd user manager available"
}

// DesiredUnits compiles portable job policy to deterministic systemd user
// unit text. Disabled jobs deliberately have no installed timer.
func (scheduler SystemdUser) DesiredUnits(jobs []config.MaintenanceJob) (map[string]string, error) {
	result := map[string]string{}
	for _, job := range jobs {
		if !validSchedulerJobName(job.Name) {
			return nil, fmt.Errorf("unsafe maintenance job name for scheduler unit")
		}
		// DesiredUnits can be called independently of config validation. Reparse
		// the schedule before placing it in OnCalendar so untrusted fields cannot
		// inject systemd unit content.
		if _, err := config.ParseMaintenanceSchedule(job.Schedule.String()); err != nil {
			return nil, fmt.Errorf("invalid maintenance schedule for scheduler unit: %w", err)
		}
		if !job.Enabled {
			continue
		}
		serviceName := scheduler.ServiceName(job.Name)
		timerName := scheduler.TimerName(job.Name)
		service, err := scheduler.renderService(job, serviceName)
		if err != nil {
			return nil, err
		}
		timer, err := scheduler.renderTimer(job, serviceName)
		if err != nil {
			return nil, err
		}
		result[serviceName] = service
		result[timerName] = timer
	}
	return result, nil
}

func validSchedulerJobName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for index, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') || (index == 0 && !(character >= 'a' && character <= 'z')) {
			return false
		}
	}
	return true
}

func (scheduler SystemdUser) ServiceName(job string) string {
	return "bebop-maintenance-" + job + ".service"
}

func (scheduler SystemdUser) TimerName(job string) string {
	return "bebop-maintenance-" + job + ".timer"
}

func (scheduler SystemdUser) renderService(job config.MaintenanceJob, serviceName string) (string, error) {
	fingerprint, err := job.Fingerprint()
	if err != nil {
		return "", err
	}
	arguments := []string{scheduler.Executable, "maintenance", "run", "--scheduled", "--config", scheduler.ConfigPath, "--inventory", scheduler.InventoryPath, job.Name}
	escaped := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		value, err := escapeSystemdArgument(argument)
		if err != nil {
			return "", err
		}
		escaped = append(escaped, value)
	}
	workingDirectory, err := escapeSystemdArgument(scheduler.ProjectRoot)
	if err != nil {
		return "", err
	}
	return unitHeader + "# Bebop-Job-Fingerprint: " + fingerprint + "\n[Unit]\nDescription=Bebop maintenance " + job.Name + "\n\n[Service]\nType=oneshot\nWorkingDirectory=" + workingDirectory + "\nExecStart=" + strings.Join(escaped, " ") + "\n", nil
}

func (scheduler SystemdUser) renderTimer(job config.MaintenanceJob, serviceName string) (string, error) {
	onCalendar, err := systemdCalendar(job.Schedule)
	if err != nil {
		return "", err
	}
	unit, err := escapeSystemdArgument(serviceName)
	if err != nil {
		return "", err
	}
	return unitHeader + "[Unit]\nDescription=Bebop maintenance timer " + job.Name + "\n\n[Timer]\nOnCalendar=" + onCalendar + "\nPersistent=true\nUnit=" + unit + "\n\n[Install]\nWantedBy=timers.target\n", nil
}

func systemdCalendar(schedule config.MaintenanceSchedule) (string, error) {
	switch schedule.Kind {
	case "hourly":
		return "hourly", nil
	case "daily":
		return "*-*-* " + schedule.At + ":00", nil
	case "weekly":
		day := map[string]string{"mon": "Mon", "tue": "Tue", "wed": "Wed", "thu": "Thu", "fri": "Fri", "sat": "Sat", "sun": "Sun"}[schedule.Weekday]
		if day == "" {
			return "", fmt.Errorf("unsupported maintenance weekday %q", schedule.Weekday)
		}
		return day + " *-*-* " + schedule.At + ":00", nil
	default:
		return "", fmt.Errorf("unsupported maintenance schedule %q", schedule.Kind)
	}
}

func escapeSystemdArgument(value string) (string, error) {
	if value == "" {
		return "\"\"", nil
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", fmt.Errorf("systemd unit argument contains a control character")
		}
	}
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return "\"" + value + "\"", nil
}

func UnitFingerprint(contents string) string {
	sum := sha256.Sum256([]byte(contents))
	return hex.EncodeToString(sum[:])
}

func (scheduler SystemdUser) Status(ctx context.Context, jobs []config.MaintenanceJob) ([]SystemdStatus, error) {
	desired, err := scheduler.DesiredUnits(jobs)
	if err != nil {
		return nil, err
	}
	runner := scheduler.run
	if runner == nil {
		runner = runCommand
	}
	program := scheduler.Systemctl
	if program == "" {
		program = "systemctl"
	}
	statuses := make([]SystemdStatus, 0, len(jobs))
	for _, job := range jobs {
		status := SystemdStatus{Job: job.Name, Backend: scheduler.Backend(), NativeID: scheduler.TimerName(job.Name), Service: scheduler.ServiceName(job.Name), Timer: scheduler.TimerName(job.Name), Enabled: job.Enabled}
		if !job.Enabled {
			_, serviceErr := os.Lstat(filepath.Join(scheduler.UnitDirectory, status.Service))
			_, timerErr := os.Lstat(filepath.Join(scheduler.UnitDirectory, status.Timer))
			if serviceErr == nil || timerErr == nil {
				status.State = "stale"
				status.Detail = "disabled job still has installed scheduler units"
			} else {
				status.State = "disabled"
			}
			statuses = append(statuses, status)
			continue
		}
		service, serviceOK := desired[status.Service]
		timer, timerOK := desired[status.Timer]
		if !serviceOK || !timerOK {
			return nil, fmt.Errorf("missing generated scheduler unit for %s", job.Name)
		}
		actualService, serviceErr := os.ReadFile(filepath.Join(scheduler.UnitDirectory, status.Service))
		actualTimer, timerErr := os.ReadFile(filepath.Join(scheduler.UnitDirectory, status.Timer))
		status.UnitFingerprint = UnitFingerprint(service)
		status.TimerFingerprint = UnitFingerprint(timer)
		status.DesiredFingerprint = schedulerArtifactFingerprint(service, timer)
		if os.IsNotExist(serviceErr) || os.IsNotExist(timerErr) {
			status.State = "missing"
			statuses = append(statuses, status)
			continue
		}
		if serviceErr != nil || timerErr != nil {
			status.State = "unit-error"
			status.Detail = "cannot read generated scheduler unit"
			statuses = append(statuses, status)
			continue
		}
		status.Installed = true
		status.ActualFingerprint = schedulerArtifactFingerprint(string(actualService), string(actualTimer))
		if string(actualService) != service || string(actualTimer) != timer {
			status.State = "stale"
			status.Detail = "unit content differs from current maintenance policy"
			statuses = append(statuses, status)
			continue
		}
		output, enabledErr := runner(ctx, program, "--user", "is-enabled", status.Timer)
		if enabledErr != nil || strings.TrimSpace(output) != "enabled" {
			status.State = "disabled"
			statuses = append(statuses, status)
			continue
		}
		status.Loaded = true
		status.State = "current"
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Job < statuses[j].Job })
	return statuses, nil
}

// Install atomically writes unit files, reloads the user manager, enables
// declared timers, and reconciles obsolete *Bebop-owned* units. It never scans
// or mutates target hosts.
func (scheduler SystemdUser) Install(ctx context.Context, jobs []config.MaintenanceJob, dryRun bool) ([]UnitChange, error) {
	desired, err := scheduler.DesiredUnits(jobs)
	if err != nil {
		return nil, err
	}
	changes, err := scheduler.changes(desired)
	if err != nil {
		return nil, err
	}
	if capability, detail := scheduler.Capability(ctx); capability != SchedulerAvailable {
		return nil, fmt.Errorf("scheduler %s: %s", capability, detail)
	}
	if dryRun {
		return changes, nil
	}
	if err := os.MkdirAll(scheduler.UnitDirectory, 0o700); err != nil {
		return nil, err
	}
	for filename, contents := range desired {
		if err := writeUnitAtomic(filepath.Join(scheduler.UnitDirectory, filename), contents); err != nil {
			return nil, err
		}
	}
	for _, change := range changes {
		if change.Action != "remove" || !strings.HasSuffix(change.Unit, ".timer") {
			continue
		}
		if _, err := scheduler.systemctl(ctx, "--user", "disable", "--now", change.Unit); err != nil {
			return nil, fmt.Errorf("disable obsolete scheduler timer %s: %w", change.Unit, err)
		}
	}
	for _, change := range changes {
		if change.Action != "remove" {
			continue
		}
		if err := os.Remove(filepath.Join(scheduler.UnitDirectory, change.Unit)); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	if _, err := scheduler.systemctl(ctx, "--user", "daemon-reload"); err != nil {
		return nil, fmt.Errorf("reload systemd user manager: %w", err)
	}
	for _, job := range jobs {
		if !job.Enabled {
			continue
		}
		if _, err := scheduler.systemctl(ctx, "--user", "enable", "--now", scheduler.TimerName(job.Name)); err != nil {
			return nil, fmt.Errorf("enable scheduler timer for %s: %w", job.Name, err)
		}
	}
	return changes, nil
}

func (scheduler SystemdUser) Uninstall(ctx context.Context, _ []config.MaintenanceJob) ([]UnitChange, error) {
	if capability, detail := scheduler.Capability(ctx); capability != SchedulerAvailable {
		return nil, fmt.Errorf("scheduler %s: %s", capability, detail)
	}
	owned, err := scheduler.ownedUnits()
	if err != nil {
		return nil, err
	}
	changes := make([]UnitChange, 0, len(owned))
	for _, filename := range owned {
		if strings.HasSuffix(filename, ".timer") {
			if _, err := scheduler.systemctl(ctx, "--user", "disable", "--now", filename); err != nil {
				return nil, fmt.Errorf("disable scheduler timer %s: %w", filename, err)
			}
		}
		if err := os.Remove(filepath.Join(scheduler.UnitDirectory, filename)); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		changes = append(changes, UnitChange{Action: "remove", Unit: filename, Backend: scheduler.Backend(), NativeID: filename})
	}
	if len(changes) > 0 {
		if _, err := scheduler.systemctl(ctx, "--user", "daemon-reload"); err != nil {
			return nil, fmt.Errorf("reload systemd user manager: %w", err)
		}
	}
	return changes, nil
}

func (scheduler SystemdUser) changes(desired map[string]string) ([]UnitChange, error) {
	owned, err := scheduler.ownedUnits()
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ownedSet := map[string]bool{}
	for _, filename := range owned {
		ownedSet[filename] = true
	}
	changes := make([]UnitChange, 0)
	for filename, contents := range desired {
		actual, err := os.ReadFile(filepath.Join(scheduler.UnitDirectory, filename))
		switch {
		case os.IsNotExist(err):
			changes = append(changes, UnitChange{Action: "install", Unit: filename, Backend: scheduler.Backend(), NativeID: filename})
		case err != nil:
			return nil, err
		case string(actual) != contents:
			changes = append(changes, UnitChange{Action: "update", Unit: filename, Backend: scheduler.Backend(), NativeID: filename})
		}
		delete(ownedSet, filename)
	}
	for filename := range ownedSet {
		changes = append(changes, UnitChange{Action: "remove", Unit: filename, Backend: scheduler.Backend(), NativeID: filename})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Unit == changes[j].Unit {
			return changes[i].Action < changes[j].Action
		}
		return changes[i].Unit < changes[j].Unit
	})
	return changes, nil
}

func (scheduler SystemdUser) ownedUnits() ([]string, error) {
	entries, err := os.ReadDir(scheduler.UnitDirectory)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(name, "bebop-maintenance-") || !(strings.HasSuffix(name, ".service") || strings.HasSuffix(name, ".timer")) {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(scheduler.UnitDirectory, name))
		if readErr == nil && strings.HasPrefix(string(contents), unitHeader) {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (scheduler SystemdUser) systemctl(ctx context.Context, arguments ...string) (string, error) {
	program := scheduler.Systemctl
	if program == "" {
		program = "systemctl"
	}
	runner := scheduler.run
	if runner == nil {
		runner = runCommand
	}
	return runner(ctx, program, arguments...)
}

func writeUnitAtomic(filename, contents string) error {
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".bebop-maintenance-unit-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.WriteString(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filename)
}

func runCommand(ctx context.Context, program string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, program, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		return strings.TrimSpace(string(output)), err
	}
	return strings.TrimSpace(string(output)), nil
}
