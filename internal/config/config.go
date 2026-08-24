// Package config loads Bebop's strict, versioned declarative configuration.
package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/pelletier/go-toml/v2"
)

const CurrentVersion = 1
const DefaultDataRoot = "/srv/bebop"
const DefaultServiceHealthTimeout = "2m"
const DefaultBackupDestination = ".bebop/backups"

type Config struct {
	Version  int       `toml:"version" json:"version"`
	Server   Server    `toml:"server" json:"server"`
	Features Features  `toml:"features" json:"features"`
	Network  Network   `toml:"network" json:"network"`
	Storage  Storage   `toml:"storage" json:"storage"`
	Backup   Backup    `toml:"backup" json:"backup"`
	Services []Service `toml:"-" json:"services,omitempty"`

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
	DataRoot string `toml:"data_root" json:"data_root"`
}
type Backup struct {
	// Destination is a controller filesystem directory. A relative value is
	// resolved from the declaring configuration file, never a target path.
	Destination string `toml:"destination" json:"destination"`
}

// Service is one user-defined workload resource. M3 supports only the built-in
// Compose provider; a service is intentionally not an application recipe.
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
	Name   string `toml:"name" json:"name"`
	Type   string `toml:"type" json:"type"`
	Volume string `toml:"volume,omitempty" json:"volume,omitempty"`
	Path   string `toml:"path,omitempty" json:"path,omitempty"`
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
		DataRoot *string `toml:"data_root"`
	} `toml:"storage"`
	Backup struct {
		Destination *string `toml:"destination"`
	} `toml:"backup"`
	Services map[string]struct {
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
	if raw.Backup.Destination != nil {
		config.Backup.Destination = *raw.Backup.Destination
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
	if err := ValidateBackupDestination(config.Backup.Destination); err != nil {
		return errs.New(errs.ConfigInvalid, err.Error(), nil)
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
				if !dockerVolumeKeyPattern.MatchString(resource.Volume) || resource.Path != "" {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" volume resources require a safe Compose volume key and no path", nil)
				}
			case "path":
				if resource.Volume != "" {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" path resources must not declare volume", nil)
				}
				if err := ValidateBackupPath(resource.Path, config.Storage.DataRoot); err != nil {
					return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+" "+err.Error(), nil)
				}
			default:
				return errs.New(errs.ConfigInvalid, "service."+service.Name+".data."+resource.Name+".type must be \"volume\" or \"path\"", nil)
			}
		}
	}
	return nil
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
	normalized.Services = append([]Service(nil), config.Services...)
	sort.Slice(normalized.Services, func(i, j int) bool { return normalized.Services[i].Name < normalized.Services[j].Name })
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
