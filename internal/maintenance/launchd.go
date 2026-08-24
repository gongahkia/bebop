package maintenance

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/config"
)

const launchdPlistHeader = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
`

const launchdManagedMarker = "<!-- Managed by Bebop. Do not edit; run bebop maintenance install. -->\n"

const launchdPath = "/usr/bin:/bin:/usr/sbin:/sbin"
const schedulerCommandTimeout = 10 * time.Second

// Launchd owns only project-scoped user LaunchAgents. It creates finite
// scheduled Bebop invocations; it never creates a daemon, LaunchDaemon, or
// target-side scheduler.
type Launchd struct {
	LaunchAgentDirectory string
	ProjectRoot          string
	ProjectID            string
	ConfigPath           string
	InventoryPath        string
	Executable           string
	Home                 string
	UID                  int
	Platform             string
	Launchctl            string
	Plutil               string
	run                  commandRunner
}

func NewLaunchdWithContext(install SchedulerContext) Launchd {
	return Launchd{
		LaunchAgentDirectory: filepath.Join(install.Home, "Library", "LaunchAgents"),
		ProjectRoot:          install.ProjectRoot,
		ProjectID:            install.ProjectID,
		ConfigPath:           install.ConfigPath,
		InventoryPath:        install.InventoryPath,
		Executable:           install.Executable,
		Home:                 install.Home,
		UID:                  install.UID,
		Platform:             install.Platform,
		Launchctl:            "launchctl",
		Plutil:               "plutil",
	}
}

func (scheduler Launchd) Backend() string { return "launchd" }

func (scheduler Launchd) Capability(ctx context.Context) (SchedulerCapability, string) {
	if scheduler.Platform != "darwin" {
		return SchedulerUnsupported, "M9 scheduler installation supports macOS LaunchAgents only on macOS controllers"
	}
	if scheduler.UID < 0 {
		return SchedulerUnavailable, "current macOS user launchd domain is unavailable"
	}
	if scheduler.run == nil {
		if _, err := exec.LookPath(scheduler.launchctlProgram()); err != nil {
			return SchedulerUnavailable, "launchctl is not available on this controller"
		}
		if _, err := exec.LookPath(scheduler.plutilProgram()); err != nil {
			return SchedulerUnavailable, "plutil is not available on this controller"
		}
		if info, err := os.Stat("/usr/bin/ssh"); err != nil || !info.Mode().IsRegular() {
			return SchedulerUnavailable, "required /usr/bin/ssh is not available for LaunchAgent maintenance jobs"
		}
	}
	if err := scheduler.checkLaunchAgentDirectory(false); err != nil {
		return SchedulerUnavailable, conciseError(err)
	}
	if _, err := scheduler.launchctl(ctx, "print", scheduler.Domain()); err != nil {
		return SchedulerUnavailable, "launchd user domain is unavailable: " + conciseError(err)
	}
	return SchedulerAvailable, "launchd user LaunchAgent domain available"
}

func (scheduler Launchd) Domain() string { return "gui/" + strconv.Itoa(scheduler.UID) }

func (scheduler Launchd) Label(job string) string {
	return "com.bebop." + scheduler.ProjectID + ".maintenance." + job
}

func (scheduler Launchd) PlistName(job string) string { return scheduler.Label(job) + ".plist" }

func (scheduler Launchd) plistPath(job string) string {
	return filepath.Join(scheduler.LaunchAgentDirectory, scheduler.PlistName(job))
}

// DesiredPlists compiles the portable maintenance schedule to deterministic
// XML. The generated ProgramArguments are direct argv values, never shell text.
func (scheduler Launchd) DesiredPlists(jobs []config.MaintenanceJob) (map[string]string, error) {
	if len(scheduler.ProjectID) != 12 || !isLowerHex(scheduler.ProjectID) {
		return nil, fmt.Errorf("invalid scheduler project identity")
	}
	result := map[string]string{}
	for _, job := range jobs {
		if !validSchedulerJobName(job.Name) {
			return nil, fmt.Errorf("unsafe maintenance job name for LaunchAgent")
		}
		if _, err := config.ParseMaintenanceSchedule(job.Schedule.String()); err != nil {
			return nil, fmt.Errorf("invalid maintenance schedule for LaunchAgent: %w", err)
		}
		if !job.Enabled {
			continue
		}
		contents, err := scheduler.renderPlist(job)
		if err != nil {
			return nil, err
		}
		result[scheduler.PlistName(job.Name)] = contents
	}
	return result, nil
}

func (scheduler Launchd) renderPlist(job config.MaintenanceJob) (string, error) {
	if scheduler.Executable == "" || !filepath.IsAbs(scheduler.Executable) || scheduler.ConfigPath == "" || !filepath.IsAbs(scheduler.ConfigPath) || scheduler.InventoryPath == "" || !filepath.IsAbs(scheduler.InventoryPath) || scheduler.ProjectRoot == "" || !filepath.IsAbs(scheduler.ProjectRoot) || scheduler.Home == "" || !filepath.IsAbs(scheduler.Home) {
		return "", fmt.Errorf("LaunchAgent requires absolute executable, project, config, inventory, and home paths")
	}
	label := scheduler.Label(job.Name)
	if !validLaunchdLabel(label) {
		return "", fmt.Errorf("invalid LaunchAgent label")
	}
	arguments := []string{scheduler.Executable, "maintenance", "run", "--scheduled", "--config", scheduler.ConfigPath, "--inventory", scheduler.InventoryPath, job.Name}
	var result strings.Builder
	result.WriteString(launchdPlistHeader)
	result.WriteString(launchdManagedMarker)
	result.WriteString("<dict>\n")
	writePlistString(&result, "  ", "Label", label)
	result.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, argument := range arguments {
		result.WriteString("    <string>")
		result.WriteString(xmlText(argument))
		result.WriteString("</string>\n")
	}
	result.WriteString("  </array>\n")
	writePlistString(&result, "  ", "WorkingDirectory", scheduler.ProjectRoot)
	result.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
	writePlistString(&result, "    ", "HOME", scheduler.Home)
	writePlistString(&result, "    ", "PATH", launchdPath)
	result.WriteString("  </dict>\n")
	writePlistString(&result, "  ", "ProcessType", "Background")
	if err := writeLaunchdSchedule(&result, job.Schedule); err != nil {
		return "", err
	}
	result.WriteString("</dict>\n</plist>\n")
	contents := result.String()
	if err := validatePlistXML(contents); err != nil {
		return "", err
	}
	return contents, nil
}

func writePlistString(output *strings.Builder, indentation, key, value string) {
	output.WriteString(indentation)
	output.WriteString("<key>")
	output.WriteString(xmlText(key))
	output.WriteString("</key>\n")
	output.WriteString(indentation)
	output.WriteString("<string>")
	output.WriteString(xmlText(value))
	output.WriteString("</string>\n")
}

func writeLaunchdSchedule(output *strings.Builder, schedule config.MaintenanceSchedule) error {
	switch schedule.Kind {
	case "hourly":
		output.WriteString("  <key>StartInterval</key>\n  <integer>3600</integer>\n")
		return nil
	case "daily", "weekly":
		hour, minute, err := launchdTime(schedule.At)
		if err != nil {
			return err
		}
		output.WriteString("  <key>StartCalendarInterval</key>\n  <dict>\n")
		if schedule.Kind == "weekly" {
			weekday, found := launchdWeekday(schedule.Weekday)
			if !found {
				return fmt.Errorf("unsupported maintenance weekday %q", schedule.Weekday)
			}
			writePlistInteger(output, "Weekday", weekday)
		}
		writePlistInteger(output, "Hour", hour)
		writePlistInteger(output, "Minute", minute)
		output.WriteString("  </dict>\n")
		return nil
	default:
		return fmt.Errorf("unsupported maintenance schedule %q", schedule.Kind)
	}
}

func writePlistInteger(output *strings.Builder, key string, value int) {
	output.WriteString("    <key>")
	output.WriteString(key)
	output.WriteString("</key>\n    <integer>")
	output.WriteString(strconv.Itoa(value))
	output.WriteString("</integer>\n")
}

func launchdTime(value string) (int, int, error) {
	if _, err := config.ParseMaintenanceTime(value); err != nil {
		return 0, 0, err
	}
	hour, _ := strconv.Atoi(value[:2])
	minute, _ := strconv.Atoi(value[3:])
	return hour, minute, nil
}

// launchd documents 0 and 7 as Sunday, then Monday through Saturday as 1-6.
func launchdWeekday(value string) (int, bool) {
	weekday, found := map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}[value]
	return weekday, found
}

func xmlText(value string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(value))
	return escaped.String()
}

func validatePlistXML(contents string) error {
	var document struct {
		XMLName xml.Name  `xml:"plist"`
		Version string    `xml:"version,attr"`
		Dict    *struct{} `xml:"dict"`
	}
	if err := xml.Unmarshal([]byte(contents), &document); err != nil {
		return fmt.Errorf("generated LaunchAgent plist is invalid XML: %w", err)
	}
	if document.XMLName.Local != "plist" || document.Version != "1.0" || document.Dict == nil {
		return fmt.Errorf("generated LaunchAgent plist has an invalid root structure")
	}
	return nil
}

func (scheduler Launchd) Status(ctx context.Context, jobs []config.MaintenanceJob) ([]SchedulerJobStatus, error) {
	desired, err := scheduler.DesiredPlists(jobs)
	if err != nil {
		return nil, err
	}
	statuses := make([]SchedulerJobStatus, 0, len(jobs))
	for _, job := range jobs {
		label := scheduler.Label(job.Name)
		filename := scheduler.plistPath(job.Name)
		status := SchedulerJobStatus{Job: job.Name, Backend: scheduler.Backend(), NativeID: label, Enabled: job.Enabled}
		contents, readErr := safeReadArtifact(filename)
		loaded, loadedErr := scheduler.loaded(ctx, label)
		if loadedErr != nil {
			return nil, loadedErr
		}
		status.Loaded = loaded
		if !job.Enabled {
			if readErr == nil || loaded {
				status.State, status.Detail = "stale", "disabled job still has an installed or loaded LaunchAgent"
			} else if errors.Is(readErr, os.ErrNotExist) {
				status.State = "disabled"
			} else {
				status.State, status.Detail = "scheduler-error", "cannot inspect LaunchAgent plist"
			}
			statuses = append(statuses, status)
			continue
		}
		desiredContents, found := desired[scheduler.PlistName(job.Name)]
		if !found {
			return nil, fmt.Errorf("missing generated LaunchAgent plist for %s", job.Name)
		}
		status.DesiredFingerprint = UnitFingerprint(desiredContents)
		switch {
		case errors.Is(readErr, os.ErrNotExist):
			if loaded {
				status.State, status.Detail = "stale", "LaunchAgent is loaded but its plist is missing"
			} else {
				status.State = "missing"
			}
		case readErr != nil:
			status.State, status.Detail = "scheduler-error", "cannot read LaunchAgent plist safely"
		default:
			status.Installed = true
			status.ActualFingerprint = UnitFingerprint(contents)
			if contents != desiredContents {
				status.State, status.Detail = "stale", "LaunchAgent plist content differs from current maintenance policy"
			} else if !loaded {
				status.State, status.Detail = "disabled", "LaunchAgent plist is installed but not loaded"
			} else {
				status.State = "current"
			}
		}
		statuses = append(statuses, status)
	}
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Job < statuses[j].Job })
	return statuses, nil
}

func (scheduler Launchd) Install(ctx context.Context, jobs []config.MaintenanceJob, dryRun bool) ([]UnitChange, error) {
	desired, err := scheduler.DesiredPlists(jobs)
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
	if err := scheduler.checkLaunchAgentDirectory(true); err != nil {
		return nil, err
	}
	for _, change := range changes {
		if change.Action != "update" && change.Action != "remove" {
			continue
		}
		if err := scheduler.bootout(ctx, change.NativeID); err != nil {
			return nil, fmt.Errorf("boot out LaunchAgent %s: %w", change.NativeID, err)
		}
	}
	for _, change := range changes {
		if change.Action != "remove" {
			continue
		}
		if err := removeSafeArtifact(filepath.Join(scheduler.LaunchAgentDirectory, change.Unit)); err != nil {
			return nil, fmt.Errorf("remove obsolete LaunchAgent %s: %w", change.NativeID, err)
		}
	}
	for _, change := range changes {
		if change.Action != "install" && change.Action != "update" {
			continue
		}
		contents := desired[change.Unit]
		if err := scheduler.writePlistAtomic(ctx, filepath.Join(scheduler.LaunchAgentDirectory, change.Unit), contents); err != nil {
			return nil, fmt.Errorf("write LaunchAgent %s: %w", change.NativeID, err)
		}
	}
	for _, job := range jobs {
		if !job.Enabled {
			continue
		}
		loaded, err := scheduler.loaded(ctx, scheduler.Label(job.Name))
		if err != nil {
			return nil, err
		}
		if !loaded {
			if _, err := scheduler.launchctl(ctx, "bootstrap", scheduler.Domain(), scheduler.plistPath(job.Name)); err != nil {
				return nil, fmt.Errorf("bootstrap LaunchAgent %s: %w", scheduler.Label(job.Name), err)
			}
		}
	}
	statuses, err := scheduler.Status(ctx, jobs)
	if err != nil {
		return nil, err
	}
	for _, status := range statuses {
		if (status.Enabled && status.State != "current") || (!status.Enabled && status.State != "disabled") {
			return nil, fmt.Errorf("LaunchAgent %s did not reconcile: %s", status.NativeID, status.State)
		}
	}
	return changes, nil
}

func (scheduler Launchd) Uninstall(ctx context.Context, _ []config.MaintenanceJob) ([]UnitChange, error) {
	if capability, detail := scheduler.Capability(ctx); capability != SchedulerAvailable {
		return nil, fmt.Errorf("scheduler %s: %s", capability, detail)
	}
	owned, err := scheduler.ownedPlists()
	if err != nil {
		return nil, err
	}
	changes := make([]UnitChange, 0, len(owned))
	for _, filename := range owned {
		label := strings.TrimSuffix(filename, ".plist")
		if err := scheduler.bootout(ctx, label); err != nil {
			return nil, fmt.Errorf("boot out LaunchAgent %s: %w", label, err)
		}
		if err := removeSafeArtifact(filepath.Join(scheduler.LaunchAgentDirectory, filename)); err != nil {
			return nil, fmt.Errorf("remove LaunchAgent %s: %w", label, err)
		}
		changes = append(changes, UnitChange{Action: "remove", Unit: filename, Backend: scheduler.Backend(), NativeID: label})
	}
	return changes, nil
}

func (scheduler Launchd) changes(desired map[string]string) ([]UnitChange, error) {
	owned, err := scheduler.ownedPlists()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	ownedSet := map[string]bool{}
	for _, filename := range owned {
		ownedSet[filename] = true
	}
	changes := []UnitChange{}
	for filename, contents := range desired {
		actual, err := safeReadArtifact(filepath.Join(scheduler.LaunchAgentDirectory, filename))
		switch {
		case errors.Is(err, os.ErrNotExist):
			changes = append(changes, UnitChange{Action: "install", Unit: filename, Backend: scheduler.Backend(), NativeID: strings.TrimSuffix(filename, ".plist")})
		case err != nil:
			return nil, err
		case actual != contents:
			changes = append(changes, UnitChange{Action: "update", Unit: filename, Backend: scheduler.Backend(), NativeID: strings.TrimSuffix(filename, ".plist")})
		}
		delete(ownedSet, filename)
	}
	for filename := range ownedSet {
		changes = append(changes, UnitChange{Action: "remove", Unit: filename, Backend: scheduler.Backend(), NativeID: strings.TrimSuffix(filename, ".plist")})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Action != changes[j].Action {
			return changes[i].Action < changes[j].Action
		}
		return changes[i].Unit < changes[j].Unit
	})
	return changes, nil
}

func (scheduler Launchd) ownedPlists() ([]string, error) {
	entries, err := os.ReadDir(scheduler.LaunchAgentDirectory)
	if err != nil {
		return nil, err
	}
	prefix := "com.bebop." + scheduler.ProjectID + ".maintenance."
	result := []string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".plist") {
			continue
		}
		contents, readErr := safeReadArtifact(filepath.Join(scheduler.LaunchAgentDirectory, name))
		label := strings.TrimSuffix(name, ".plist")
		if readErr == nil && strings.Contains(contents, launchdManagedMarker) && strings.Contains(contents, "<string>"+xmlText(label)+"</string>") && strings.Contains(contents, "<string>"+xmlText(scheduler.ConfigPath)+"</string>") {
			result = append(result, name)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (scheduler Launchd) loaded(ctx context.Context, label string) (bool, error) {
	output, err := scheduler.launchctl(ctx, "print", scheduler.Domain()+"/"+label)
	if err == nil {
		return true, nil
	}
	if launchdAbsent(output, err) {
		return false, nil
	}
	return false, fmt.Errorf("inspect LaunchAgent %s: %w", label, err)
}

func (scheduler Launchd) bootout(ctx context.Context, label string) error {
	output, err := scheduler.launchctl(ctx, "bootout", scheduler.Domain()+"/"+label)
	if err == nil || launchdAbsent(output, err) {
		return nil
	}
	return err
}

func launchdAbsent(output string, err error) bool {
	if err == nil {
		return false
	}
	value := strings.ToLower(output + " " + err.Error())
	return strings.Contains(value, "could not find service") || strings.Contains(value, "not found") || strings.Contains(value, "no such process") || strings.Contains(value, "not loaded")
}

func (scheduler Launchd) launchctl(ctx context.Context, arguments ...string) (string, error) {
	return scheduler.command(ctx, scheduler.launchctlProgram(), arguments...)
}

func (scheduler Launchd) command(ctx context.Context, program string, arguments ...string) (string, error) {
	limited, cancel := schedulerContext(ctx)
	defer cancel()
	runner := scheduler.run
	if runner == nil {
		runner = runCommand
	}
	return runner(limited, program, arguments...)
}

func schedulerContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, found := ctx.Deadline(); found {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, schedulerCommandTimeout)
}

func (scheduler Launchd) launchctlProgram() string {
	if scheduler.Launchctl != "" {
		return scheduler.Launchctl
	}
	return "launchctl"
}

func (scheduler Launchd) plutilProgram() string {
	if scheduler.Plutil != "" {
		return scheduler.Plutil
	}
	return "plutil"
}

func (scheduler Launchd) checkLaunchAgentDirectory(create bool) error {
	info, err := os.Lstat(scheduler.LaunchAgentDirectory)
	if errors.Is(err, os.ErrNotExist) {
		if !create {
			parent := filepath.Dir(scheduler.LaunchAgentDirectory)
			parentInfo, parentErr := os.Stat(parent)
			if parentErr != nil || !parentInfo.IsDir() {
				return fmt.Errorf("LaunchAgents directory parent is unavailable")
			}
			return nil
		}
		if err := os.MkdirAll(scheduler.LaunchAgentDirectory, 0o700); err != nil {
			return fmt.Errorf("create LaunchAgents directory: %w", err)
		}
		info, err = os.Lstat(scheduler.LaunchAgentDirectory)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("LaunchAgents directory must be a real non-writable directory")
	}
	return nil
}

func (scheduler Launchd) writePlistAtomic(ctx context.Context, filename, contents string) error {
	if err := validatePlistXML(contents); err != nil {
		return err
	}
	if !schedulerPathContains(scheduler.LaunchAgentDirectory, filename) || filepath.Dir(filename) != scheduler.LaunchAgentDirectory {
		return fmt.Errorf("LaunchAgent path escapes its directory")
	}
	if info, err := os.Lstat(filename); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("refuse to replace non-regular LaunchAgent plist")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.CreateTemp(scheduler.LaunchAgentDirectory, ".bebop-launchagent-*")
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
	if _, err := scheduler.command(ctx, scheduler.plutilProgram(), "-lint", temporaryName); err != nil {
		return fmt.Errorf("validate LaunchAgent plist: %w", err)
	}
	return os.Rename(temporaryName, filename)
}

func safeReadArtifact(filename string) (string, error) {
	info, err := os.Lstat(filename)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", fmt.Errorf("scheduler artifact is not a regular file")
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	return string(contents), nil
}

func removeSafeArtifact(filename string) error {
	info, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("refuse to remove non-regular scheduler artifact")
	}
	return os.Remove(filename)
}

func validLaunchdLabel(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '.' || character == '-') {
			return false
		}
	}
	return true
}

func isLowerHex(value string) bool {
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
