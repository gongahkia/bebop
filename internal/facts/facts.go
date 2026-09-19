// Package facts contains normalized, transport-independent target observations.
package facts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

type HostFacts struct {
	Target              string           `json:"target"`
	Hostname            string           `json:"hostname"`
	MachineID           string           `json:"machine_id,omitempty"`
	OS                  OS               `json:"os"`
	Architecture        string           `json:"architecture"`
	ArchitectureKnown   bool             `json:"architecture_known"`
	Kernel              string           `json:"kernel"`
	PackageManager      string           `json:"package_manager"`
	PackageDatabase     string           `json:"package_database,omitempty"`
	InitSystem          string           `json:"init_system"`
	Systemd             bool             `json:"systemd"`
	EffectiveUser       string           `json:"effective_user"`
	SudoAvailable       bool             `json:"sudo_available"`
	SSH                 SSH              `json:"ssh"`
	Docker              Docker           `json:"docker"`
	Services            []Service        `json:"services,omitempty"`
	Tailscale           Tailscale        `json:"tailscale"`
	AutomaticUpdates    AutomaticUpdates `json:"automatic_updates"`
	SELinux             SELinux          `json:"selinux"`
	Firewall            Firewall         `json:"firewall"`
	MemoryKiB           int64            `json:"memory_kib"`
	RootFilesystem      Filesystem       `json:"root_filesystem"`
	MutationBlocked     bool             `json:"mutation_blocked,omitempty"`
	MutationBlockReason string           `json:"mutation_block_reason,omitempty"`
	UnconfiguredStorage []StorageDevice  `json:"unconfigured_storage,omitempty"`
	Storage             Storage          `json:"storage"`
	DataRoot            Directory        `json:"data_root"`
}

type OS struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	VersionID       string `json:"version_id"`
	BuildID         string `json:"build_id,omitempty"`
	VersionCodename string `json:"version_codename"`
	PlatformID      string `json:"platform_id,omitempty"`
	Family          string `json:"family"`
	Supported       bool   `json:"supported"`
}

func (o OS) Display() string {
	if o.Name == "" {
		return o.ID
	}
	if o.VersionID == "" {
		return o.Name
	}
	return o.Name + " " + o.VersionID
}

// IsSupported repeats release gates at fact-consumption boundaries so
// hand-constructed or deserialized facts cannot accidentally broaden support.
func (o OS) IsSupported() bool {
	if !o.Supported {
		return false
	}
	switch o.ID {
	case "fedora":
		return o.VersionID == "43" || o.VersionID == "44"
	case "rocky", "almalinux":
		return o.VersionID == "9.8" || o.VersionID == "10.2"
	case "centos":
		return (o.VersionID == "9" && o.PlatformID == "platform:el9" && o.Name == "CentOS Stream") || (o.VersionID == "10" && o.PlatformID == "platform:el10" && o.Name == "CentOS Stream")
	case "opensuse-leap":
		return o.VersionID == "16.0"
	case "opensuse-tumbleweed":
		return true
	case "arch":
		return o.BuildID == "rolling"
	default:
		return true
	}
}

// SupportsArchitecture adds the few reviewed architecture restrictions that
// are part of an operating-system support policy. Most Bebop capabilities are
// architecture-neutral; official Arch Linux support is deliberately x86_64
// only.
func (o OS) SupportsArchitecture(architecture string) bool {
	if !o.IsSupported() {
		return false
	}
	return o.ID != "arch" || architecture == "amd64"
}

type SSH struct {
	Installed             bool   `json:"installed"`
	Service               string `json:"service"`
	ServiceEnabled        bool   `json:"service_enabled"`
	ServiceActive         bool   `json:"service_active"`
	ConfigValid           bool   `json:"config_valid"`
	DropInSupported       bool   `json:"drop_in_supported"`
	FirstDropIn           string `json:"first_drop_in,omitempty"`
	HardeningEffective    bool   `json:"hardening_effective"`
	AuthorizedKeysPresent bool   `json:"authorized_keys_present"`
	BebopDropIn           string `json:"bebop_drop_in,omitempty"`
}

type Docker struct {
	Installed               bool   `json:"installed"`
	PackageSetComplete      bool   `json:"package_set_complete,omitempty"`
	PackageSetAvailable     bool   `json:"package_set_available,omitempty"`
	ConflictingPackages     bool   `json:"conflicting_packages,omitempty"`
	RepositoryState         string `json:"repository_state,omitempty"`
	RepositoryPolicy        string `json:"repository_policy,omitempty"`
	ServiceEnabled          bool   `json:"service_enabled"`
	ServiceActive           bool   `json:"service_active"`
	Responsive              bool   `json:"responsive"`
	ComposeAvailable        bool   `json:"compose_available"`
	ComposePackageAvailable string `json:"compose_package_available,omitempty"`
}

// Service is a normalized view of one declared Compose project. Deployment
// facts concern only Bebop's replaceable source tree; runtime facts come from
// Docker labels and container state rather than controller-side metadata.
type Service struct {
	Name                 string `json:"name"`
	Project              string `json:"project"`
	DesiredState         string `json:"desired_state"`
	DeploymentPresent    bool   `json:"deployment_present"`
	DeploymentUnsafe     bool   `json:"deployment_unsafe,omitempty"`
	DeploymentDigest     string `json:"deployment_digest,omitempty"`
	Runtime              string `json:"runtime"`
	Health               string `json:"health"`
	ContainerCount       int    `json:"container_count"`
	SecretFingerprint    string `json:"-"`
	PlacementFingerprint string `json:"placement_fingerprint,omitempty"`
}

type Tailscale struct {
	Installed        bool   `json:"installed"`
	PackageAvailable bool   `json:"package_available,omitempty"`
	ServiceEnabled   bool   `json:"service_enabled"`
	ServiceActive    bool   `json:"service_active"`
	Connected        bool   `json:"connected"`
	BackendState     string `json:"backend_state,omitempty"`
	RepositoryState  string `json:"repository_state,omitempty"`
}

type AutomaticUpdates struct {
	Installed         bool   `json:"installed"`
	PackageAvailable  bool   `json:"package_available,omitempty"`
	Enabled           bool   `json:"enabled"`
	ConfigState       string `json:"config_state,omitempty"`
	ConflictingTimers bool   `json:"conflicting_timers,omitempty"`
}

// SELinux records only the normalized enforcement state. It is relevant to
// whether a declared persistent bind may safely be shared with a Compose
// service and Bebop's backup helper; raw policy output is deliberately omitted.
type SELinux struct {
	Mode string `json:"mode"`
}

type Firewall struct {
	UFWAvailable bool `json:"ufw_available"`
	UFWActive    bool `json:"ufw_active"`
	OtherActive  bool `json:"other_active"`
}

type Filesystem struct {
	Source       string `json:"source,omitempty"`
	Type         string `json:"type,omitempty"`
	SizeKiB      int64  `json:"size_kib,omitempty"`
	AvailableKiB int64  `json:"available_kib,omitempty"`
	ReadOnly     bool   `json:"read_only,omitempty"`
}

// StorageDevice is inspection-only. M0/M1 never creates a plan action from it.
type StorageDevice struct {
	Name      string `json:"name"`
	SizeBytes int64  `json:"size_bytes"`
	Transport string `json:"transport,omitempty"`
}

// Storage is a normalized Linux storage topology. It is deliberately factual:
// desired mount names and placement policy belong to config/storage, not to
// inspection. Capacity values are shown to operators but only policy outcomes
// participate in stale-plan protection.
type Storage struct {
	Available    bool                 `json:"available"`
	Devices      []BlockDevice        `json:"devices,omitempty"`
	Mounts       []StorageMount       `json:"mounts,omitempty"`
	MountConfigs []StorageMountConfig `json:"mount_configs,omitempty"`
	Policy       []StoragePolicy      `json:"policy,omitempty"`
}

// StoragePolicy is config-relative, non-volatile inspection output. It records
// whether declared placement and thresholds are currently satisfied without
// putting exact free-space telemetry into a saved-plan fingerprint.
type StoragePolicy struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

// StorageMountConfig is a narrowly-scoped inspection of one declared
// managed-mount fstab mapping. It contains no fstab contents, only whether an
// equivalent external mapping is safe, Bebop's exact marker is present, or a
// conflicting mapping requires operator attention.
type StorageMountConfig struct {
	Name  string `json:"name"`
	State string `json:"state"`
}

type BlockDevice struct {
	Path       string   `json:"path"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	SizeBytes  int64    `json:"size_bytes,omitempty"`
	Filesystem string   `json:"filesystem,omitempty"`
	Label      string   `json:"label,omitempty"`
	UUID       string   `json:"uuid,omitempty"`
	ReadOnly   bool     `json:"read_only,omitempty"`
	Removable  bool     `json:"removable,omitempty"`
	Transport  string   `json:"transport,omitempty"`
	Mounts     []string `json:"mounts,omitempty"`
}

type StorageMount struct {
	Target         string   `json:"target"`
	Source         string   `json:"source"`
	Filesystem     string   `json:"filesystem,omitempty"`
	UUID           string   `json:"uuid,omitempty"`
	Options        []string `json:"options,omitempty"`
	SizeBytes      int64    `json:"size_bytes,omitempty"`
	AvailableBytes int64    `json:"available_bytes,omitempty"`
	ReadOnly       bool     `json:"read_only,omitempty"`
}

type Directory struct {
	Path     string `json:"path"`
	Exists   bool   `json:"exists"`
	Mode     string `json:"mode,omitempty"`
	UID      int    `json:"uid,omitempty"`
	GID      int    `json:"gid,omitempty"`
	Writable bool   `json:"writable"`
}

// Identity identifies a host independently of an SSH endpoint. Machine ID is
// preferred; hostname and OS are a conservative fallback for unusual targets
// where /etc/machine-id is unavailable.
type Identity struct {
	MachineID string `json:"machine_id,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	OSID      string `json:"os_id"`
	OSVersion string `json:"os_version"`
}

func (host HostFacts) Identity() Identity {
	return Identity{MachineID: host.MachineID, Hostname: host.Hostname, OSID: host.OS.ID, OSVersion: host.OS.VersionID}
}

func (identity Identity) Matches(current Identity) bool {
	if identity.MachineID != "" {
		return current.MachineID != "" && identity.MachineID == current.MachineID
	}
	return identity.Hostname != "" && identity.Hostname == current.Hostname && identity.OSID == current.OSID && identity.OSVersion == current.OSVersion
}

// ConvergenceSnapshot contains only facts consumed by M0/M2 planning or its
// warnings. Volatile telemetry such as kernel, memory, filesystem free space,
// and transport timing is deliberately omitted from stale-plan protection.
type ConvergenceSnapshot struct {
	OS                  OS                `json:"os"`
	Architecture        string            `json:"architecture"`
	ArchitectureKnown   bool              `json:"architecture_known"`
	PackageManager      string            `json:"package_manager"`
	PackageDatabase     string            `json:"package_database,omitempty"`
	Systemd             bool              `json:"systemd"`
	EffectiveUser       string            `json:"effective_user"`
	SudoAvailable       bool              `json:"sudo_available"`
	SSH                 SSH               `json:"ssh"`
	Docker              Docker            `json:"docker"`
	Services            []ServiceSnapshot `json:"services,omitempty"`
	Tailscale           Tailscale         `json:"tailscale"`
	AutomaticUpdates    AutomaticUpdates  `json:"automatic_updates"`
	SELinux             SELinux           `json:"selinux"`
	Firewall            Firewall          `json:"firewall"`
	UnconfiguredStorage []StorageDevice   `json:"unconfigured_storage,omitempty"`
	Storage             StorageSnapshot   `json:"storage"`
	DataRoot            Directory         `json:"data_root"`
	MutationBlocked     bool              `json:"mutation_blocked,omitempty"`
}

// StorageSnapshot intentionally records only topology and mount state. Exact
// free space is volatile; configured threshold outcomes are calculated by the
// storage module and placed in plan actions/preconditions instead.
type StorageSnapshot struct {
	Available    bool                 `json:"available"`
	MountConfigs []StorageMountConfig `json:"mount_configs,omitempty"`
	Policy       []StoragePolicy      `json:"policy,omitempty"`
}

type StorageMountStable struct {
	Target     string `json:"target"`
	Source     string `json:"source"`
	Filesystem string `json:"filesystem,omitempty"`
	UUID       string `json:"uuid,omitempty"`
	ReadOnly   bool   `json:"read_only,omitempty"`
}

// ServiceSnapshot adds the keyed secret fingerprint only to the internal
// convergence hash. Status, doctor, inspect JSON, and artifacts never render
// it, while a changed managed secret marker still invalidates a reviewed plan.
type ServiceSnapshot struct {
	Name                 string `json:"name"`
	Project              string `json:"project"`
	DesiredState         string `json:"desired_state"`
	DeploymentPresent    bool   `json:"deployment_present"`
	DeploymentUnsafe     bool   `json:"deployment_unsafe,omitempty"`
	DeploymentDigest     string `json:"deployment_digest,omitempty"`
	Runtime              string `json:"runtime"`
	Health               string `json:"health"`
	ContainerCount       int    `json:"container_count"`
	SecretFingerprint    string `json:"secret_fingerprint,omitempty"`
	PlacementFingerprint string `json:"placement_fingerprint,omitempty"`
}

func (host HostFacts) ConvergenceSnapshot() ConvergenceSnapshot {
	storage := append([]StorageDevice(nil), host.UnconfiguredStorage...)
	sort.Slice(storage, func(i, j int) bool { return storage[i].Name < storage[j].Name })
	services := make([]ServiceSnapshot, 0, len(host.Services))
	for _, service := range host.Services {
		services = append(services, ServiceSnapshot{Name: service.Name, Project: service.Project, DesiredState: service.DesiredState, DeploymentPresent: service.DeploymentPresent, DeploymentUnsafe: service.DeploymentUnsafe, DeploymentDigest: service.DeploymentDigest, Runtime: service.Runtime, Health: service.Health, ContainerCount: service.ContainerCount, SecretFingerprint: service.SecretFingerprint, PlacementFingerprint: service.PlacementFingerprint})
	}
	sort.Slice(services, func(i, j int) bool { return services[i].Name < services[j].Name })
	policy := append([]StoragePolicy(nil), host.Storage.Policy...)
	sort.Slice(policy, func(i, j int) bool { return policy[i].Name < policy[j].Name })
	mountConfigs := append([]StorageMountConfig(nil), host.Storage.MountConfigs...)
	sort.Slice(mountConfigs, func(i, j int) bool { return mountConfigs[i].Name < mountConfigs[j].Name })
	os := host.OS
	// Tumbleweed snapshot dates and Arch's absent/non-release VERSION_ID are
	// not release gates or machine identity. Package/repository facts still
	// stale a plan when their state changes.
	if os.ID == "opensuse-tumbleweed" || os.ID == "arch" {
		os.VersionID = ""
	}
	return ConvergenceSnapshot{
		OS: os, Architecture: host.Architecture, ArchitectureKnown: host.ArchitectureKnown,
		PackageManager: host.PackageManager, PackageDatabase: host.PackageDatabase, Systemd: host.Systemd, EffectiveUser: host.EffectiveUser,
		SudoAvailable: host.SudoAvailable, SSH: host.SSH, Docker: host.Docker,
		Tailscale: host.Tailscale, AutomaticUpdates: host.AutomaticUpdates, SELinux: host.SELinux, Firewall: host.Firewall,
		UnconfiguredStorage: storage, Storage: StorageSnapshot{Available: host.Storage.Available, MountConfigs: mountConfigs, Policy: policy}, DataRoot: host.DataRoot, MutationBlocked: host.MutationBlocked, Services: services,
	}
}

func (host HostFacts) ConvergenceFingerprint() (string, error) {
	encoded, err := json.Marshal(host.ConvergenceSnapshot())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
