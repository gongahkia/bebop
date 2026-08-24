package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
)

// SchedulerAdapter decides when a typed maintenance invocation starts. It
// never executes a maintenance operation itself: every native artifact invokes
// the same `bebop maintenance run --scheduled` entrypoint.
type SchedulerAdapter interface {
	Backend() string
	Capability(context.Context) (SchedulerCapability, string)
	Status(context.Context, []config.MaintenanceJob) ([]SchedulerJobStatus, error)
	Install(context.Context, []config.MaintenanceJob, bool) ([]UnitChange, error)
	Uninstall(context.Context, []config.MaintenanceJob) ([]UnitChange, error)
}

// SchedulerJobStatus is the backend-neutral view consumed by the CLI. Native
// names and artifact digests are diagnostic metadata; the MaintenanceJob
// fingerprint remains the scheduler-independent policy identity.
type SchedulerJobStatus struct {
	Job                string `json:"job"`
	Backend            string `json:"backend"`
	NativeID           string `json:"native_id"`
	State              string `json:"state"`
	DesiredFingerprint string `json:"desired_fingerprint,omitempty"`
	ActualFingerprint  string `json:"actual_fingerprint,omitempty"`
	Installed          bool   `json:"installed"`
	Loaded             bool   `json:"loaded"`
	Enabled            bool   `json:"enabled"`
	Detail             string `json:"detail,omitempty"`

	// Service, Timer, UnitFingerprint, and TimerFingerprint retain M7's JSON
	// shape for systemd clients while the generic fields describe every backend.
	Service          string `json:"service,omitempty"`
	Timer            string `json:"timer,omitempty"`
	UnitFingerprint  string `json:"unit_fingerprint,omitempty"`
	TimerFingerprint string `json:"timer_fingerprint,omitempty"`
}

// UnitChange is historical M7 naming retained for CLI compatibility. Unit is
// the native filename for systemd and launchd; NativeID is a unit or label.
type UnitChange struct {
	Action   string `json:"action"`
	Unit     string `json:"unit"`
	Backend  string `json:"backend,omitempty"`
	NativeID string `json:"native_id,omitempty"`
}

// SchedulerContext binds generated native artifacts to one controller project.
// Paths are absolute, cleaned, and resolved through existing symlinks before
// artifact generation so relocation changes desired content deterministically.
type SchedulerContext struct {
	Platform      string
	ProjectRoot   string
	ProjectID     string
	ConfigPath    string
	InventoryPath string
	Executable    string
	Home          string
	UID           int
}

func NewSchedulerContext(configPath, inventoryPath string) (SchedulerContext, error) {
	executable, err := os.Executable()
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("resolve Bebop executable: %w", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("resolve controller home directory: %w", err)
	}
	return newSchedulerContext(configPath, inventoryPath, executable, home, runtime.GOOS, os.Getuid())
}

func newSchedulerContext(configPath, inventoryPath, executable, home, platform string, uid int) (SchedulerContext, error) {
	absConfig, err := filepath.Abs(configPath)
	if err != nil {
		return SchedulerContext{}, err
	}
	absConfig, err = filepath.EvalSymlinks(absConfig)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("resolve maintenance configuration path: %w", err)
	}
	info, err := os.Stat(absConfig)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("inspect maintenance configuration path: %w", err)
	}
	if !info.Mode().IsRegular() {
		return SchedulerContext{}, fmt.Errorf("maintenance configuration path must be a regular file")
	}
	absInventory, err := filepath.Abs(inventoryPath)
	if err != nil {
		return SchedulerContext{}, err
	}
	if resolved, resolveErr := filepath.EvalSymlinks(absInventory); resolveErr == nil {
		absInventory = resolved
	} else if !os.IsNotExist(resolveErr) {
		return SchedulerContext{}, fmt.Errorf("resolve maintenance inventory path: %w", resolveErr)
	}
	if inventoryInfo, inventoryErr := os.Stat(absInventory); inventoryErr == nil && !inventoryInfo.Mode().IsRegular() {
		return SchedulerContext{}, fmt.Errorf("maintenance inventory path must be a regular file")
	} else if inventoryErr != nil && !os.IsNotExist(inventoryErr) {
		return SchedulerContext{}, fmt.Errorf("inspect maintenance inventory path: %w", inventoryErr)
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("resolve Bebop executable path: %w", err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("resolve Bebop executable path: %w", err)
	}
	executableInfo, err := os.Stat(executable)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("inspect Bebop executable path: %w", err)
	}
	if !executableInfo.Mode().IsRegular() {
		return SchedulerContext{}, fmt.Errorf("Bebop executable path must be a regular file")
	}
	home, err = filepath.Abs(home)
	if err != nil {
		return SchedulerContext{}, err
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("resolve controller home directory: %w", err)
	}
	homeInfo, err := os.Stat(home)
	if err != nil {
		return SchedulerContext{}, fmt.Errorf("inspect controller home directory: %w", err)
	}
	if !homeInfo.IsDir() {
		return SchedulerContext{}, fmt.Errorf("controller home path must be a directory")
	}
	if isTransientSchedulerExecutable(executable) {
		return SchedulerContext{}, fmt.Errorf("Bebop executable is in a temporary directory; install a stable binary before installing maintenance scheduling")
	}
	projectRoot := filepath.Dir(absConfig)
	return SchedulerContext{Platform: platform, ProjectRoot: projectRoot, ProjectID: SchedulerProjectID(projectRoot), ConfigPath: absConfig, InventoryPath: absInventory, Executable: executable, Home: home, UID: uid}, nil
}

func isTransientSchedulerExecutable(executable string) bool {
	temporary, err := filepath.Abs(os.TempDir())
	return err == nil && schedulerPathContains(temporary, executable)
}

// SchedulerProjectID isolates scheduler artifacts from different Bebop
// projects owned by the same controller user. It is deterministic and does not
// disclose the project path in native filenames or labels.
func SchedulerProjectID(projectRoot string) string {
	normalized := filepath.Clean(projectRoot)
	if absolute, err := filepath.Abs(normalized); err == nil {
		normalized = absolute
	}
	normalized = filepath.ToSlash(normalized)
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])[:12]
}

func schedulerArtifactFingerprint(contents ...string) string {
	hash := sha256.New()
	for _, content := range contents {
		_, _ = hash.Write([]byte(content))
		_, _ = hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// NewScheduler is the sole production scheduler resolver. Platform selection
// is intentionally centralized; CLI and maintenance runtime stay backend-free.
func NewScheduler(configPath, inventoryPath string) (SchedulerAdapter, error) {
	install, err := NewSchedulerContext(configPath, inventoryPath)
	if err != nil {
		return nil, err
	}
	return ResolveScheduler(install)
}

func ResolveScheduler(install SchedulerContext) (SchedulerAdapter, error) {
	platform := install.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	switch platform {
	case "linux":
		scheduler, err := NewSystemdUserWithContext(install)
		return scheduler, err
	case "darwin":
		return NewLaunchdWithContext(install), nil
	default:
		return UnsupportedScheduler{platform: platform}, nil
	}
}

type UnsupportedScheduler struct{ platform string }

func (scheduler UnsupportedScheduler) Backend() string { return "unsupported" }

func (scheduler UnsupportedScheduler) Capability(context.Context) (SchedulerCapability, string) {
	platform := scheduler.platform
	if platform == "" {
		platform = runtime.GOOS
	}
	return SchedulerUnsupported, "native maintenance scheduling is unsupported on " + platform
}

func (scheduler UnsupportedScheduler) Status(context.Context, []config.MaintenanceJob) ([]SchedulerJobStatus, error) {
	return nil, nil
}

func (scheduler UnsupportedScheduler) Install(context.Context, []config.MaintenanceJob, bool) ([]UnitChange, error) {
	return nil, fmt.Errorf("scheduler %s: native maintenance scheduling is unsupported on %s", SchedulerUnsupported, scheduler.platform)
}

func (scheduler UnsupportedScheduler) Uninstall(context.Context, []config.MaintenanceJob) ([]UnitChange, error) {
	return nil, fmt.Errorf("scheduler %s: native maintenance scheduling is unsupported on %s", SchedulerUnsupported, scheduler.platform)
}

func schedulerPathContains(root, value string) bool {
	relative, err := filepath.Rel(root, value)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
