// Package config loads Bebop's strict, versioned declarative configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/pelletier/go-toml/v2"
)

const CurrentVersion = 1
const DefaultDataRoot = "/srv/bebop"
const DefaultServiceHealthTimeout = "2m"
const DefaultBackupDestination = ".bebop/backups"
const DefaultMaintenanceHistoryDirectory = ".bebop/history"
const DefaultMaintenanceHistoryMaxEntries = 500
const DefaultNotificationStateDirectory = ".bebop/notifications"
const DefaultNotificationHistoryMaxEntries = 1_000

type Config struct {
	Version  int      `toml:"version" json:"version"`
	Server   Server   `toml:"server" json:"server"`
	Features Features `toml:"features" json:"features"`
	Network  Network  `toml:"network" json:"network"`
	Storage  Storage  `toml:"storage" json:"storage"`
	Backup   Backup   `toml:"backup" json:"backup"`
	// Maintenance is controller-side policy. It is optional so existing
	// single-target configurations retain their M0-M6 behavior unchanged.
	Maintenance *Maintenance `toml:"-" json:"maintenance,omitempty"`
	// Notifications are controller-side operational policy. They never affect
	// target convergence or saved-plan validity.
	Notifications *Notifications `toml:"-" json:"notifications,omitempty"`
	Services      []Service      `toml:"-" json:"services,omitempty"`

	// sourceDirectory is controller-local context, never desired state. It is
	// populated by LoadFile so service source paths resolve beside the config
	// declaration rather than relative to the controller's current directory.
	sourceDirectory string
}

type Server struct {
	Name string `toml:"name" json:"name"`
}
type Features struct {
	AutomaticUpdates bool `toml:"automatic_updates" json:"automatic_updates"`
	SSHHardening     bool `toml:"ssh_hardening" json:"ssh_hardening"`
	Docker           bool `toml:"docker" json:"docker"`
	Tailscale        bool `toml:"tailscale" json:"tailscale"`
}
type Network struct {
	Firewall string `toml:"firewall" json:"firewall"`
}
type Storage struct {
	DataRoot  string            `toml:"data_root" json:"data_root"`
	Resources []StorageResource `toml:"-" json:"resources,omitempty"`
}

// StorageResource is an explicit, already-formatted target filesystem that
// Bebop may use for declared persistent bind paths. It deliberately contains
// no block-device selector: Bebop M6 never formats, partitions, or chooses a
// disk. UUID is the stable filesystem identity; a Linux device path is only
// inspection detail and is never desired state.
type StorageResource struct {
	Name                 string `toml:"-" json:"name"`
	Mount                string `toml:"mount" json:"mount"`
	FilesystemUUID       string `toml:"filesystem_uuid" json:"filesystem_uuid"`
	FilesystemType       string `toml:"filesystem_type,omitempty" json:"filesystem_type,omitempty"`
	MinimumCapacityBytes int64  `toml:"minimum_capacity_bytes,omitempty" json:"minimum_capacity_bytes,omitempty"`
	MinimumFreeBytes     int64  `toml:"minimum_free_bytes,omitempty" json:"minimum_free_bytes,omitempty"`
	ManagedMount         bool   `toml:"managed_mount,omitempty" json:"managed_mount,omitempty"`
}
type Backup struct {
	// Destination is a controller filesystem directory. A relative value is
	// resolved from the declaring configuration file, never a target path.
	Destination string `toml:"destination" json:"destination"`
}

// Service is one user-defined workload resource. M3 supports only the built-in
// Compose provider; M5 recipes materialize into this same generic model.
type Service struct {
	Name          string         `toml:"-" json:"name"`
	Type          string         `toml:"type" json:"type"`
	Source        string         `toml:"source" json:"source"`
	State         string         `toml:"state" json:"state"`
	SecretEnvFile string         `toml:"secret_env_file,omitempty" json:"secret_env_file,omitempty"`
	HealthTimeout string         `toml:"health_timeout,omitempty" json:"health_timeout,omitempty"`
	Data          []DataResource `toml:"data,omitempty" json:"data,omitempty"`
	Backup        ServiceBackup  `toml:"backup" json:"backup"`
}

// DataResource is an explicit authorization boundary. Bebop never infers
// backup ownership from Docker volumes or bind mounts found on a target.
type DataResource struct {
	Name    string `toml:"name" json:"name"`
	Type    string `toml:"type" json:"type"`
	Volume  string `toml:"volume,omitempty" json:"volume,omitempty"`
	Path    string `toml:"path,omitempty" json:"path,omitempty"`
	Storage string `toml:"storage,omitempty" json:"storage,omitempty"`
}

// ServiceBackup intentionally offers only generic consistency choices. It is
// not a hook or database-backup framework.
type ServiceBackup struct {
	Consistency string `toml:"consistency" json:"consistency"`
}

type rawConfig struct {
	Version int `toml:"version"`
	Server  struct {
		Name *string `toml:"name"`
	} `toml:"server"`
	Features struct {
		AutomaticUpdates *bool `toml:"automatic_updates"`
		SSHHardening     *bool `toml:"ssh_hardening"`
		Docker           *bool `toml:"docker"`
		Tailscale        *bool `toml:"tailscale"`
	} `toml:"features"`
	Network struct {
		Firewall *string `toml:"firewall"`
	} `toml:"network"`
	Storage struct {
		DataRoot  *string                       `toml:"data_root"`
		Resources map[string]rawStorageResource `toml:"resources"`
	} `toml:"storage"`
	Backup struct {
		Destination *string `toml:"destination"`
	} `toml:"backup"`
	Maintenance   *rawMaintenance   `toml:"maintenance"`
	Notifications *rawNotifications `toml:"notifications"`
	Services      map[string]struct {
		Type          *string        `toml:"type"`
		Source        *string        `toml:"source"`
		State         *string        `toml:"state"`
		SecretEnvFile *string        `toml:"secret_env_file"`
		HealthTimeout *string        `toml:"health_timeout"`
		Data          []DataResource `toml:"data"`
		Backup        struct {
			Consistency *string `toml:"consistency"`
		} `toml:"backup"`
	} `toml:"services"`
}

type rawStorageResource struct {
	Mount                *string `toml:"mount"`
	FilesystemUUID       *string `toml:"filesystem_uuid"`
	FilesystemType       *string `toml:"filesystem_type"`
	MinimumCapacityBytes *int64  `toml:"minimum_capacity_bytes"`
	MinimumFreeBytes     *int64  `toml:"minimum_free_bytes"`
	MinimumCapacity      *string `toml:"minimum_capacity"`
	MinimumFree          *string `toml:"minimum_free"`
	ManagedMount         *bool   `toml:"managed_mount"`
}

func Defaults() Config {
	return Config{Version: CurrentVersion, Server: Server{Name: "home"}, Features: Features{AutomaticUpdates: true, SSHHardening: true, Docker: true, Tailscale: true}, Network: Network{Firewall: "disabled"}, Storage: Storage{DataRoot: DefaultDataRoot}, Backup: Backup{Destination: DefaultBackupDestination}}
}

func LoadFile(filename string) (Config, error) {
	absFilename, err := filepath.Abs(filename)
	if err != nil {
		return Config{}, errs.New(errs.ConfigInvalid, "resolve configuration path", err)
	}
	file, err := os.Open(absFilename)
	if err != nil {
		return Config{}, errs.New(errs.ConfigInvalid, "cannot read configuration", err)
	}
	defer file.Close()
	result, err := Decode(file)
	if err != nil {
		return Config{}, err
	}
	result.sourceDirectory = filepath.Dir(absFilename)
	return result, nil
}

func Decode(reader io.Reader) (Config, error) {
	var raw rawConfig
	decoder := toml.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, errs.New(errs.ConfigInvalid, "invalid bebop.toml", err)
	}
	config := Defaults()
	config.Version = raw.Version
	if raw.Server.Name != nil {
		config.Server.Name = *raw.Server.Name
	}
	if raw.Features.AutomaticUpdates != nil {
		config.Features.AutomaticUpdates = *raw.Features.AutomaticUpdates
	}
	if raw.Features.SSHHardening != nil {
		config.Features.SSHHardening = *raw.Features.SSHHardening
	}
	if raw.Features.Docker != nil {
		config.Features.Docker = *raw.Features.Docker
	}
	if raw.Features.Tailscale != nil {
		config.Features.Tailscale = *raw.Features.Tailscale
	}
	if raw.Network.Firewall != nil {
		config.Network.Firewall = *raw.Network.Firewall
	}
	if raw.Storage.DataRoot != nil {
		config.Storage.DataRoot = *raw.Storage.DataRoot
	}
	storageNames := make([]string, 0, len(raw.Storage.Resources))
	for name := range raw.Storage.Resources {
		storageNames = append(storageNames, name)
	}
	sort.Strings(storageNames)
	for _, name := range storageNames {
		rawResource := raw.Storage.Resources[name]
		resource := StorageResource{Name: name}
		if rawResource.Mount != nil {
			resource.Mount = *rawResource.Mount
		}
		if rawResource.FilesystemUUID != nil {
			resource.FilesystemUUID = *rawResource.FilesystemUUID
		}
		if rawResource.FilesystemType != nil {
			resource.FilesystemType = *rawResource.FilesystemType
		}
		if rawResource.MinimumCapacityBytes != nil {
			resource.MinimumCapacityBytes = *rawResource.MinimumCapacityBytes
		}
		if rawResource.MinimumFreeBytes != nil {
			resource.MinimumFreeBytes = *rawResource.MinimumFreeBytes
		}
		if rawResource.MinimumCapacity != nil {
			if rawResource.MinimumCapacityBytes != nil {
				return Config{}, errs.New(errs.ConfigInvalid, "storage.resources."+name+" may use either minimum_capacity or minimum_capacity_bytes, not both", nil)
			}
			bytes, parseErr := ParseByteSize(*rawResource.MinimumCapacity)
			if parseErr != nil {
				return Config{}, errs.New(errs.ConfigInvalid, "storage.resources."+name+".minimum_capacity "+parseErr.Error(), nil)
			}
			resource.MinimumCapacityBytes = bytes
		}
		if rawResource.MinimumFree != nil {
			if rawResource.MinimumFreeBytes != nil {
				return Config{}, errs.New(errs.ConfigInvalid, "storage.resources."+name+" may use either minimum_free or minimum_free_bytes, not both", nil)
			}
			bytes, parseErr := ParseByteSize(*rawResource.MinimumFree)
			if parseErr != nil {
				return Config{}, errs.New(errs.ConfigInvalid, "storage.resources."+name+".minimum_free "+parseErr.Error(), nil)
			}
			resource.MinimumFreeBytes = bytes
		}
		if rawResource.ManagedMount != nil {
			resource.ManagedMount = *rawResource.ManagedMount
		}
		config.Storage.Resources = append(config.Storage.Resources, resource)
	}
	if raw.Backup.Destination != nil {
		config.Backup.Destination = *raw.Backup.Destination
	}
	if raw.Maintenance != nil {
		maintenance, maintenanceErr := decodeMaintenance(*raw.Maintenance)
		if maintenanceErr != nil {
			return Config{}, maintenanceErr
		}
		config.Maintenance = &maintenance
	}
	if raw.Notifications != nil {
		notifications, notificationErr := decodeNotifications(*raw.Notifications)
		if notificationErr != nil {
			return Config{}, notificationErr
		}
		config.Notifications = &notifications
	}
	serviceNames := make([]string, 0, len(raw.Services))
	for name := range raw.Services {
		serviceNames = append(serviceNames, name)
	}
	sort.Strings(serviceNames)
	for _, name := range serviceNames {
		rawService := raw.Services[name]
		service := Service{Name: name, State: "running", HealthTimeout: DefaultServiceHealthTimeout, Backup: ServiceBackup{Consistency: "stop"}}
		if rawService.Type != nil {
			service.Type = *rawService.Type
		}
		if rawService.Source != nil {
			service.Source = *rawService.Source
		}
		if rawService.State != nil {
			service.State = *rawService.State
		}
		if rawService.SecretEnvFile != nil {
			service.SecretEnvFile = *rawService.SecretEnvFile
		}
		if rawService.HealthTimeout != nil {
			service.HealthTimeout = *rawService.HealthTimeout
		}
		service.Data = append([]DataResource(nil), rawService.Data...)
		if rawService.Backup.Consistency != nil {
			service.Backup.Consistency = *rawService.Backup.Consistency
		}
		config.Services = append(config.Services, service)
	}
	if err := Validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
var serviceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func Validate(config Config) error {
	if config.Version != CurrentVersion {
		return errs.New(errs.ConfigInvalid, fmt.Sprintf("unsupported configuration version %d (expected %d)", config.Version, CurrentVersion), nil)
	}
	if !namePattern.MatchString(config.Server.Name) {
		return errs.New(errs.ConfigInvalid, "server.name must be 1-63 letters, numbers, dots, underscores, or hyphens", nil)
	}
	if config.Network.Firewall != "disabled" {
		return errs.New(errs.ConfigInvalid, "network.firewall currently supports only \"disabled\"; Bebop M0 never configures firewalls", nil)
	}
	if err := ValidateDataRoot(config.Storage.DataRoot); err != nil {
		return errs.New(errs.ConfigInvalid, err.Error(), nil)
	}
	if err := validateStorageResources(config.Storage); err != nil {
		return errs.New(errs.ConfigInvalid, err.Error(), nil)
	}
	if err := ValidateBackupDestination(config.Backup.Destination); err != nil {
		return errs.New(errs.ConfigInvalid, err.Error(), nil)
	}
	if config.Maintenance != nil {
		if err := ValidateMaintenance(*config.Maintenance); err != nil {
			return errs.New(errs.ConfigInvalid, err.Error(), nil)
		}
	}
	if config.Notifications != nil {
		if err := ValidateNotifications(*config.Notifications); err != nil {
			return errs.New(errs.ConfigInvalid, err.Error(), nil)
		}
	}
	previousName := ""
	for _, service := range config.Services {
		if !serviceNamePattern.MatchString(service.Name) {
			return errs.New(errs.ConfigInvalid, "service name must be 1-63 lowercase letters, numbers, or hyphens and start with a letter", nil)
		}
		if previousName != "" && service.Name <= previousName {
			return errs.New(errs.ConfigInvalid, "services must have unique names in lexical order", nil)
		}
		previousName = service.Name
		if service.Type != "compose" {
			return errs.New(errs.ConfigInvalid, "service."+service.Name+".type currently supports only \"compose\"", nil)
		}
		if err := ValidateControllerRelativePath(service.Source, false); err != nil {
			return errs.New(errs.ConfigInvalid, "service."+service.Name+".source "+err.Error(), nil)
		}
		if service.State != "running" && service.State != "stopped" && service.State != "absent" {
			return errs.New(errs.ConfigInvalid, "service."+service.Name+".state must be \"running\", \"stopped\", or \"absent\"", nil)
		}
		if service.SecretEnvFile != "" {
			if err := ValidateControllerRelativePath(service.SecretEnvFile, true); err != nil {
				return errs.New(errs.ConfigInvalid, "service."+service.Name+".secret_env_file "+err.Error(), nil)
			}
		}
		if service.HealthTimeout == "" {
			return errs.New(errs.ConfigInvalid, "service."+service.Name+".health_timeout must not be empty", nil)
		}
		timeout, err := time.ParseDuration(service.HealthTimeout)
		if err != nil || timeout < time.Second || timeout > 30*time.Minute {
			return errs.New(errs.ConfigInvalid, "service."+service.Name+".health_timeout must be between 1s and 30m", nil)
		}
		if service.Backup.Consistency != "stop" && service.Backup.Consistency != "live" {
			return errs.New(errs.ConfigInvalid, "service."+service.Name+".backup.consistency must be \"stop\" or \"live\"", nil)
		}
		previousData := ""
		for _, resource := range service.Data {
			if !serviceNamePattern.MatchString(resource.Name) {
				return errs.New(errs.ConfigInvalid, "service."+service.Name+".data name must be 1-63 lowercase letters, numbers, or hyphens and start with a letter", nil)
			}
			if previousData != "" && resource.Name <= previousData {
				return errs.New(errs.ConfigInvalid, "service."+service.Name+".data resources must have unique names in lexical order", nil)
			}
			previousData = resource.Name
			switch resource.Type {
			case "volume":
				if !dockerVolumeKeyPattern.MatchString(resource.Volume) || resource.Path != "" || resource.Storage != "" {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" volume resources require a safe Compose volume key and no path", nil)
				}
			case "path":
				if resource.Volume != "" {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" path resources must not declare volume", nil)
				}
				resolved, err := ResolveDataPath(config.Storage, resource)
				if err != nil {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" "+err.Error(), nil)
				}
				if err := ValidateBackupPath(resolved, config.Storage.DataRoot); err != nil {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" "+err.Error(), nil)
				}
			default:
				return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+".type must be \"volume\" or \"path\"", nil)
			}
		}
	}
	return nil
}

var filesystemUUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{7,63}$`)
var filesystemTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}$`)
var byteSizePattern = regexp.MustCompile(`^([0-9]+)(KiB|MiB|GiB|TiB|KB|MB|GB|TB)$`)

// ParseByteSize accepts explicit binary (KiB..TiB) and decimal (KB..TB)
// quantities. Bare numbers are deliberately rejected in the user-facing
// schema; *_bytes remains available for generated/controller tooling.
func ParseByteSize(value string) (int64, error) {
	matches := byteSizePattern.FindStringSubmatch(value)
	if matches == nil {
		return 0, fmt.Errorf("must be an integer quantity such as 20GiB")
	}
	amount, err := strconv.ParseInt(matches[1], 10, 64)
	if err != nil || amount <= 0 {
		return 0, fmt.Errorf("must be a positive byte quantity")
	}
	multiplier := int64(1)
	switch matches[2] {
	case "KiB":
		multiplier = 1 << 10
	case "MiB":
		multiplier = 1 << 20
	case "GiB":
		multiplier = 1 << 30
	case "TiB":
		multiplier = 1 << 40
	case "KB":
		multiplier = 1000
	case "MB":
		multiplier = 1000 * 1000
	case "GB":
		multiplier = 1000 * 1000 * 1000
	case "TB":
		multiplier = 1000 * 1000 * 1000 * 1000
	}
	if amount > math.MaxInt64/multiplier {
		return 0, fmt.Errorf("overflows supported byte capacity")
	}
	return amount * multiplier, nil
}

func validateStorageResources(storage Storage) error {
	previousName := ""
	mounts := map[string]string{}
	uuids := map[string]string{}
	for _, resource := range storage.Resources {
		if !serviceNamePattern.MatchString(resource.Name) || resource.Name == "resources" {
			return fmt.Errorf("storage resource names must be 1-63 lowercase letters, numbers, or hyphens and start with a letter")
		}
		if previousName != "" && resource.Name <= previousName {
			return fmt.Errorf("storage resources must have unique names in lexical order")
		}
		previousName = resource.Name
		if err := ValidateStorageMount(resource.Mount); err != nil {
			return fmt.Errorf("storage.resources.%s.mount %w", resource.Name, err)
		}
		if !filesystemUUIDPattern.MatchString(resource.FilesystemUUID) {
			return fmt.Errorf("storage.resources.%s.filesystem_uuid must be a safe filesystem UUID", resource.Name)
		}
		if resource.FilesystemType != "" && !filesystemTypePattern.MatchString(resource.FilesystemType) {
			return fmt.Errorf("storage.resources.%s.filesystem_type must be a safe filesystem type", resource.Name)
		}
		if resource.MinimumCapacityBytes < 0 || resource.MinimumFreeBytes < 0 {
			return fmt.Errorf("storage.resources.%s capacity thresholds must not be negative", resource.Name)
		}
		if previous, found := mounts[resource.Mount]; found {
			return fmt.Errorf("storage resources %s and %s use the same mount point", previous, resource.Name)
		}
		mounts[resource.Mount] = resource.Name
		if previous, found := uuids[resource.FilesystemUUID]; found {
			return fmt.Errorf("storage resources %s and %s use the same filesystem UUID", previous, resource.Name)
		}
		uuids[resource.FilesystemUUID] = resource.Name
	}
	for _, one := range storage.Resources {
		for _, other := range storage.Resources {
			if one.Name != other.Name && strings.HasPrefix(other.Mount, one.Mount+"/") {
				return fmt.Errorf("storage mount points %s and %s must not be nested", one.Mount, other.Mount)
			}
		}
	}
	return nil
}

// ValidateStorageMount limits M6 to deliberate application-data mount points.
// It rejects root and host/system trees rather than trying to make arbitrary
// host filesystems safe to mount or manage.
func ValidateStorageMount(mount string) error {
	if mount == "" || !strings.HasPrefix(mount, "/") || strings.ContainsRune(mount, '\x00') || path.Clean(mount) != mount || mount == "/" {
		return fmt.Errorf("must be a clean absolute mount point other than /")
	}
	for _, forbidden := range []string{"/etc", "/usr", "/var", "/home", "/root", "/proc", "/sys", "/dev", "/run", "/boot", "/bin", "/lib", "/lib64", "/sbin"} {
		if mount == forbidden || strings.HasPrefix(mount, forbidden+"/") {
			return fmt.Errorf("must not cover system directory %s", forbidden)
		}
	}
	for _, allowed := range []string{"/srv/", "/mnt/", "/data/"} {
		if strings.HasPrefix(mount, allowed) {
			return nil
		}
	}
	return fmt.Errorf("must be below /srv, /mnt, or /data")
}

// ResolveDataPath returns the target path authorized by one data declaration.
// Storage-relative paths intentionally use POSIX semantics because targets are
// Linux, irrespective of the controller platform.
func ResolveDataPath(storage Storage, resource DataResource) (string, error) {
	if resource.Storage == "" {
		if resource.Path == "" {
			return "", fmt.Errorf("path must not be empty")
		}
		return resource.Path, nil
	}
	if !serviceNamePattern.MatchString(resource.Storage) {
		return "", fmt.Errorf("storage must name a configured storage resource")
	}
	if resource.Path == "" || strings.HasPrefix(resource.Path, "/") || strings.ContainsRune(resource.Path, '\x00') || path.Clean(resource.Path) != resource.Path || resource.Path == "." || strings.HasPrefix(resource.Path, "../") || resource.Path == ".." {
		return "", fmt.Errorf("storage-relative path must be a clean non-empty relative target path")
	}
	for _, candidate := range storage.Resources {
		if candidate.Name == resource.Storage {
			return path.Join(candidate.Mount, resource.Path), nil
		}
	}
	return "", fmt.Errorf("storage %q is not declared", resource.Storage)
}

var dockerVolumeKeyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

func ValidateBackupDestination(destination string) error {
	if destination == "" || strings.ContainsRune(destination, '\x00') {
		return fmt.Errorf("backup.destination must be a non-empty controller path")
	}
	if filepath.IsAbs(destination) {
		if filepath.Clean(destination) != destination || destination == string(filepath.Separator) {
			return fmt.Errorf("backup.destination must be a clean directory path other than the filesystem root")
		}
		return nil
	}
	if err := ValidateControllerRelativePath(destination, false); err != nil {
		return fmt.Errorf("backup.destination %w", err)
	}
	return nil
}

// ValidateBackupPath constrains target bind-path backup to ordinary application
// data locations. Broad host trees and Bebop's replaceable deployment tree are
// intentionally out of scope for M4.
func ValidateBackupPath(targetPath, dataRoot string) error {
	if targetPath == "" || !strings.HasPrefix(targetPath, "/") || strings.ContainsRune(targetPath, '\x00') || path.Clean(targetPath) != targetPath || targetPath == "/" {
		return fmt.Errorf("path must be a clean absolute target path")
	}
	for _, forbidden := range []string{"/etc", "/usr", "/var", "/home", "/root", "/proc", "/sys", "/dev", "/run", "/boot", "/bin", "/lib", "/lib64", "/sbin"} {
		if targetPath == forbidden || strings.HasPrefix(targetPath, forbidden+"/") {
			return fmt.Errorf("path must not cover system directory %s", forbidden)
		}
	}
	if targetPath == dataRoot || strings.HasPrefix(targetPath, dataRoot+"/") {
		return fmt.Errorf("path must not be inside Bebop's replaceable deployment data root")
	}
	for _, allowed := range []string{"/srv/", "/mnt/", "/data/"} {
		if strings.HasPrefix(targetPath, allowed) {
			return nil
		}
	}
	return fmt.Errorf("path must be below /srv, /mnt, or /data")
}

func ValidateDataRoot(root string) error {
	if root == "" || !strings.HasPrefix(root, "/") {
		return fmt.Errorf("storage.data_root must be an absolute path")
	}
	if root == "/" || path.Clean(root) != root || strings.ContainsRune(root, '\x00') {
		return fmt.Errorf("storage.data_root must be a clean absolute path other than /")
	}
	if len(root) > 240 {
		return fmt.Errorf("storage.data_root is too long")
	}
	return nil
}

// ValidateControllerRelativePath applies controller filesystem semantics. It
// intentionally rejects both slash styles so a checked-in config has the same
// containment boundary on Unix and Windows controllers.
func ValidateControllerRelativePath(value string, file bool) error {
	if value == "" || strings.ContainsRune(value, '\x00') || filepath.IsAbs(value) || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\") {
		return fmt.Errorf("must be a non-empty relative path")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("must not contain control characters")
		}
	}
	converted := filepath.FromSlash(strings.ReplaceAll(value, "\\", "/"))
	cleaned := filepath.Clean(converted)
	if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("must stay within the configuration directory")
	}
	if file && cleaned == "." {
		return fmt.Errorf("must name a file")
	}
	return nil
}

// SourceDirectory is controller-only information established by LoadFile.
// Decode callers without a file may set it with WithSourceDirectory in tests
// or embedding code.
func (config Config) SourceDirectory() string { return config.sourceDirectory }

func WithSourceDirectory(config Config, directory string) Config {
	config.sourceDirectory = directory
	return config
}

// AdoptStorageResource appends one narrowly-scoped storage declaration while
// preserving all user-authored TOML bytes outside that new table. Adoption is
// controller-side inventory/configuration work only; it never contacts or
// mutates a target. The caller is responsible for proving observed topology.
func AdoptStorageResource(filename string, resource StorageResource) error {
	cfg, err := LoadFile(filename)
	if err != nil {
		return err
	}
	probe := cfg.Storage
	probe.Resources = append(probe.Resources, resource)
	sort.Slice(probe.Resources, func(i, j int) bool { return probe.Resources[i].Name < probe.Resources[j].Name })
	if err := validateStorageResources(probe); err != nil {
		return errs.New(errs.ConfigInvalid, err.Error(), nil)
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		return errs.New(errs.ConfigInvalid, "read configuration for storage adoption", err)
	}
	// A decoded duplicate is rejected above. This extra exact-header check keeps
	// an unusual duplicate TOML layout from being silently shadowed by append.
	header := "[storage.resources." + resource.Name + "]"
	if strings.Contains(string(contents), header) {
		return errs.New(errs.ConfigInvalid, "storage resource "+resource.Name+" already exists", nil)
	}
	var addition strings.Builder
	fmt.Fprintf(&addition, "\n%s\nmount = %q\nfilesystem_uuid = %q\n", header, resource.Mount, resource.FilesystemUUID)
	if resource.FilesystemType != "" {
		fmt.Fprintf(&addition, "filesystem_type = %q\n", resource.FilesystemType)
	}
	if resource.MinimumCapacityBytes > 0 {
		fmt.Fprintf(&addition, "minimum_capacity_bytes = %d\n", resource.MinimumCapacityBytes)
	}
	if resource.MinimumFreeBytes > 0 {
		fmt.Fprintf(&addition, "minimum_free_bytes = %d\n", resource.MinimumFreeBytes)
	}
	if resource.ManagedMount {
		addition.WriteString("managed_mount = true\n")
	}
	info, err := os.Stat(filename)
	if err != nil {
		return errs.New(errs.ConfigInvalid, "stat configuration for storage adoption", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".bebop-config-*")
	if err != nil {
		return errs.New(errs.ConfigInvalid, "create temporary configuration", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(append(contents, []byte(addition.String())...)); err != nil {
		_ = temporary.Close()
		return errs.New(errs.ConfigInvalid, "write adopted storage configuration", err)
	}
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		_ = temporary.Close()
		return errs.New(errs.ConfigInvalid, "set adopted configuration permissions", err)
	}
	if err := temporary.Close(); err != nil {
		return errs.New(errs.ConfigInvalid, "close adopted configuration", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return errs.New(errs.ConfigInvalid, "atomically write adopted storage configuration", err)
	}
	return nil
}

func Starter() string {
	config := Defaults()
	// The fixed template is intentionally timestamp-free and reproducible.
	return fmt.Sprintf(`version = %d

[server]
name = %q

[features]
automatic_updates = %t
ssh_hardening = %t
docker = %t
tailscale = %t

[network]
firewall = %q

[storage]
data_root = %q
`, config.Version, config.Server.Name, config.Features.AutomaticUpdates, config.Features.SSHHardening, config.Features.Docker, config.Features.Tailscale, config.Network.Firewall, config.Storage.DataRoot)
}

// Fingerprint hashes the normalized semantic configuration, not the source
// TOML bytes. Whitespace, key order, and omitted default values therefore do
// not invalidate a reviewed plan, while a desired-state change does.
func Fingerprint(config Config) (string, error) {
	if err := Validate(config); err != nil {
		return "", err
	}
	normalized := config
	// Maintenance is controller-side operational policy, not target desired
	// state. Changing a timer must not stale an otherwise reviewed convergence
	// plan; maintenance jobs carry their own deterministic fingerprints.
	normalized.Maintenance = nil
	normalized.Notifications = nil
	normalized.Services = append([]Service(nil), config.Services...)
	sort.Slice(normalized.Services, func(i, j int) bool { return normalized.Services[i].Name < normalized.Services[j].Name })
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
