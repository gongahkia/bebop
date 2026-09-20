package facts

import (
	"fmt"
	"strings"
)

// ReleaseModel describes how a reviewed platform advances. It is support
// policy, not an instruction to perform system upgrades.
type ReleaseModel string

const (
	ReleaseFixed   ReleaseModel = "fixed"
	ReleaseRolling ReleaseModel = "rolling"
	ReleaseStream  ReleaseModel = "stream"
)

// AutomaticUpdatePolicy makes the deliberately unsupported rolling-update
// cases distinct from an omitted implementation.
type AutomaticUpdatePolicy string

const (
	AutomaticUpdatesSupported   AutomaticUpdatePolicy = "supported"
	AutomaticUpdatesUnsupported AutomaticUpdatePolicy = "intentionally_unsupported"
)

// RootPersistencePolicy records whether ordinary mutable-root checks are
// sufficient or the reviewed platform requires a conventional persistent host.
type RootPersistencePolicy string

const (
	RootPersistenceStandard   RootPersistencePolicy = "standard"
	RootPersistencePersistent RootPersistencePolicy = "persistent_host_required"
)

// Capability is a reviewed product capability, not a package-manager command.
// The list is deliberately finite so a new platform cannot gain accidental
// support through an omitted/default value.
type Capability string

const (
	CapabilityInspect                Capability = "inspect"
	CapabilityBootstrap              Capability = "bootstrap"
	CapabilityDoctor                 Capability = "doctor"
	CapabilityStatus                 Capability = "status"
	CapabilityPlan                   Capability = "plan"
	CapabilityApply                  Capability = "apply"
	CapabilitySavedPlanApply         Capability = "saved_plan_apply"
	CapabilityDataRoot               Capability = "data_root"
	CapabilityAutomaticUpdates       Capability = "automatic_updates"
	CapabilityDocker                 Capability = "docker"
	CapabilityComposeV2              Capability = "compose_v2"
	CapabilityTailscale              Capability = "tailscale"
	CapabilitySSHHardening           Capability = "ssh_hardening"
	CapabilityStorageAssessment      Capability = "storage_assessment"
	CapabilityManagedMounts          Capability = "managed_mounts"
	CapabilityComposeServices        Capability = "compose_services"
	CapabilityBackups                Capability = "backups"
	CapabilityRestore                Capability = "restore"
	CapabilityMaintenanceBackup      Capability = "maintenance_backup"
	CapabilityMaintenanceDoctor      Capability = "maintenance_doctor"
	CapabilityMaintenanceUpdateCheck Capability = "maintenance_update_check"
	CapabilityNotifications          Capability = "notifications"
	CapabilityRecipes                Capability = "recipes"
)

var requiredCapabilities = []Capability{
	CapabilityInspect,
	CapabilityBootstrap,
	CapabilityDoctor,
	CapabilityStatus,
	CapabilityPlan,
	CapabilityApply,
	CapabilitySavedPlanApply,
	CapabilityDataRoot,
	CapabilityAutomaticUpdates,
	CapabilityDocker,
	CapabilityComposeV2,
	CapabilityTailscale,
	CapabilitySSHHardening,
	CapabilityStorageAssessment,
	CapabilityManagedMounts,
	CapabilityComposeServices,
	CapabilityBackups,
	CapabilityRestore,
	CapabilityMaintenanceBackup,
	CapabilityMaintenanceDoctor,
	CapabilityMaintenanceUpdateCheck,
	CapabilityNotifications,
	CapabilityRecipes,
}

type CapabilityState string

const (
	CapabilitySupported                CapabilityState = "supported"
	CapabilitySupportedWithConstraint  CapabilityState = "supported_with_constraint"
	CapabilityIntentionallyUnsupported CapabilityState = "intentionally_unsupported"
)

// PlatformMatch deliberately uses exact os-release fields. In particular, it
// never consults ID_LIKE.
type PlatformMatch struct {
	ID              string
	VersionID       string
	VersionPrefix   string
	NumericTriplet  bool
	VersionCodename string
	BuildID         string
	PlatformID      string
	Name            string
}

func (match PlatformMatch) matches(os OS) bool {
	if os.ID != match.ID {
		return false
	}
	if match.VersionID != "" && os.VersionID != match.VersionID {
		return false
	}
	if match.VersionPrefix != "" && !strings.HasPrefix(os.VersionID, match.VersionPrefix) {
		return false
	}
	if match.NumericTriplet && !numericVersionTriplet(os.VersionID) {
		return false
	}
	if match.VersionCodename != "" && os.VersionCodename != match.VersionCodename {
		return false
	}
	if match.BuildID != "" && os.BuildID != match.BuildID {
		return false
	}
	if match.PlatformID != "" && os.PlatformID != match.PlatformID {
		return false
	}
	return match.Name == "" || os.Name == match.Name
}

// PlatformPolicy is the reviewed product-support contract for one exact
// platform combination. Package names, repository definitions, and service
// scripts remain in their capability modules.
type PlatformPolicy struct {
	Key                   string
	DisplayName           string
	Family                string
	Match                 PlatformMatch
	Architectures         []string
	Libcs                 []string
	PackageManager        string
	PackageDatabase       string
	InitSystem            InitSystem
	ReleaseModel          ReleaseModel
	AutomaticUpdates      AutomaticUpdatePolicy
	RootPersistence       RootPersistencePolicy
	RequiresMutationTools bool
	ManualToolRemediation string
	Capabilities          []CapabilityState
}

func (policy PlatformPolicy) SupportsArchitecture(architecture string) bool {
	for _, supported := range policy.Architectures {
		if architecture == supported {
			return true
		}
	}
	return false
}

func (policy PlatformPolicy) SupportsLibc(libc string) bool {
	if len(policy.Libcs) == 0 {
		return libc == ""
	}
	for _, supported := range policy.Libcs {
		if libc == supported {
			return true
		}
	}
	return false
}

func (policy PlatformPolicy) Capability(capability Capability) CapabilityState {
	for index, current := range requiredCapabilities {
		if current == capability {
			return policy.Capabilities[index]
		}
	}
	return ""
}

func (policy PlatformPolicy) Validate() error {
	if policy.Key == "" || policy.DisplayName == "" || policy.Family == "" || policy.Match.ID == "" {
		return fmt.Errorf("platform policy has incomplete identity")
	}
	if len(policy.Architectures) == 0 || policy.PackageManager == "" || policy.InitSystem == InitSystemUnknown || policy.ReleaseModel == "" || policy.AutomaticUpdates == "" || policy.RootPersistence == "" {
		return fmt.Errorf("platform policy %s has incomplete required support fields", policy.Key)
	}
	if len(policy.Capabilities) != len(requiredCapabilities) {
		return fmt.Errorf("platform policy %s has incomplete capability parity", policy.Key)
	}
	for index, state := range policy.Capabilities {
		switch state {
		case CapabilitySupported, CapabilitySupportedWithConstraint, CapabilityIntentionallyUnsupported:
		default:
			return fmt.Errorf("platform policy %s has invalid %s capability state %q", policy.Key, requiredCapabilities[index], state)
		}
	}
	if policy.Capability(CapabilityAutomaticUpdates) == CapabilityIntentionallyUnsupported && policy.AutomaticUpdates != AutomaticUpdatesUnsupported {
		return fmt.Errorf("platform policy %s has inconsistent automatic-update policy", policy.Key)
	}
	if policy.Capability(CapabilityAutomaticUpdates) != CapabilityIntentionallyUnsupported && policy.AutomaticUpdates != AutomaticUpdatesSupported {
		return fmt.Errorf("platform policy %s has inconsistent automatic-update capability", policy.Key)
	}
	return nil
}

func capabilities(automatic AutomaticUpdatePolicy, constrained bool) []CapabilityState {
	result := make([]CapabilityState, len(requiredCapabilities))
	for index := range result {
		result[index] = CapabilitySupported
	}
	if constrained {
		for index, capability := range requiredCapabilities {
			if capability != CapabilityAutomaticUpdates {
				result[index] = CapabilitySupportedWithConstraint
			}
		}
	}
	for index, capability := range requiredCapabilities {
		if capability == CapabilityAutomaticUpdates && automatic == AutomaticUpdatesUnsupported {
			result[index] = CapabilityIntentionallyUnsupported
		}
	}
	return result
}

func policy(key, display, family, id, version, prefix, codename, build, platform, name string, architectures, libcs []string, manager, database string, init InitSystem, release ReleaseModel, automatic AutomaticUpdatePolicy, root RootPersistencePolicy, requiresTools bool, remediation string) PlatformPolicy {
	return PlatformPolicy{
		Key: key, DisplayName: display, Family: family,
		Match:         PlatformMatch{ID: id, VersionID: version, VersionPrefix: prefix, NumericTriplet: id == "alpine" && prefix != "", VersionCodename: codename, BuildID: build, PlatformID: platform, Name: name},
		Architectures: append([]string(nil), architectures...), Libcs: append([]string(nil), libcs...), PackageManager: manager, PackageDatabase: database,
		InitSystem: init, ReleaseModel: release, AutomaticUpdates: automatic, RootPersistence: root,
		RequiresMutationTools: requiresTools, ManualToolRemediation: remediation, Capabilities: capabilities(automatic, root == RootPersistencePersistent),
	}
}

var platformPolicies = []PlatformPolicy{
	policy("debian-12", "Debian 12", "debian", "debian", "12", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("debian-13", "Debian 13", "debian", "debian", "13", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("ubuntu-22.04", "Ubuntu 22.04", "ubuntu", "ubuntu", "22.04", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("ubuntu-24.04", "Ubuntu 24.04", "ubuntu", "ubuntu", "24.04", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("raspberry-pi-os-12", "Raspberry Pi OS 12", "raspberry-pi-os", "raspbian", "12", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("raspberry-pi-os-13", "Raspberry Pi OS 13", "raspberry-pi-os", "raspbian", "13", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("fedora-43", "Fedora 43", "fedora", "fedora", "43", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "dnf5", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("fedora-44", "Fedora 44", "fedora", "fedora", "44", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "dnf5", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("rocky-9.8", "Rocky Linux 9.8", "enterprise-linux", "rocky", "9.8", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "dnf", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("rocky-10.2", "Rocky Linux 10.2", "enterprise-linux", "rocky", "10.2", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "dnf", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("alma-9.8", "AlmaLinux 9.8", "enterprise-linux", "almalinux", "9.8", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "dnf", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("alma-10.2", "AlmaLinux 10.2", "enterprise-linux", "almalinux", "10.2", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "dnf", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("centos-stream-9", "CentOS Stream 9", "enterprise-linux", "centos", "9", "", "", "", "platform:el9", "CentOS Stream", []string{"amd64", "arm64"}, nil, "dnf", "rpm", InitSystemSystemd, ReleaseStream, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("centos-stream-10", "CentOS Stream 10", "enterprise-linux", "centos", "10", "", "", "", "platform:el10", "CentOS Stream", []string{"amd64", "arm64"}, nil, "dnf", "rpm", InitSystemSystemd, ReleaseStream, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("opensuse-leap-16.0", "openSUSE Leap 16.0", "opensuse", "opensuse-leap", "16.0", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "zypper", "rpm", InitSystemSystemd, ReleaseFixed, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("opensuse-tumbleweed", "openSUSE Tumbleweed", "opensuse", "opensuse-tumbleweed", "", "", "", "", "", "", []string{"amd64", "arm64"}, nil, "zypper", "rpm", InitSystemSystemd, ReleaseRolling, AutomaticUpdatesSupported, RootPersistenceStandard, false, ""),
	policy("arch", "Arch Linux", "arch", "arch", "", "", "", "rolling", "", "", []string{"amd64"}, nil, "pacman", "", InitSystemSystemd, ReleaseRolling, AutomaticUpdatesUnsupported, RootPersistenceStandard, false, ""),
	policy("alpine-3.24", "Alpine Linux 3.24.x", "alpine", "alpine", "", "3.24.", "", "", "", "", []string{"amd64", "arm64"}, nil, "apk", "", InitSystemOpenRC, ReleaseFixed, AutomaticUpdatesSupported, RootPersistencePersistent, true, "apk add flock findmnt lsblk"),
	policy("void", "Void Linux", "void", "void", "", "", "", "", "", "", []string{"amd64", "arm64"}, []string{"glibc", "musl"}, "xbps", "", InitSystemRunit, ReleaseRolling, AutomaticUpdatesUnsupported, RootPersistencePersistent, true, "xbps-install -S util-linux"),
	policy("devuan-6", "Devuan 6 Excalibur", "devuan", "devuan", "6", "", "excalibur", "", "", "", []string{"amd64", "arm64"}, nil, "apt", "dpkg", InitSystemSysV, ReleaseFixed, AutomaticUpdatesSupported, RootPersistencePersistent, true, "apt-get install flock util-linux"),
	policy("artix", "Artix Linux", "artix", "artix", "", "", "", "rolling", "", "", []string{"amd64"}, nil, "pacman", "", InitSystemDinit, ReleaseRolling, AutomaticUpdatesUnsupported, RootPersistencePersistent, true, "pacman -S util-linux"),
}

// PlatformPolicies returns a stable copy of the compile-time reviewed matrix.
func PlatformPolicies() []PlatformPolicy {
	result := make([]PlatformPolicy, len(platformPolicies))
	for index, current := range platformPolicies {
		result[index] = current
		result[index].Architectures = append([]string(nil), current.Architectures...)
		result[index].Libcs = append([]string(nil), current.Libcs...)
		result[index].Capabilities = append([]CapabilityState(nil), current.Capabilities...)
	}
	return result
}

// PlatformPolicyFor returns the exact reviewed combination for os.
func PlatformPolicyFor(os OS) (PlatformPolicy, bool) {
	for _, policy := range platformPolicies {
		if policy.Match.matches(os) {
			return policy, true
		}
	}
	return PlatformPolicy{}, false
}

// ReviewedPlatformsForID describes exact current entries for an observed ID,
// including unreviewed releases of a known family. It is useful for doctor
// remediation and deliberately returns stable matrix order.
func ReviewedPlatformsForID(id string) []PlatformPolicy {
	result := make([]PlatformPolicy, 0)
	for _, policy := range platformPolicies {
		if policy.Match.ID == id {
			result = append(result, policy)
		}
	}
	return result
}

func ReviewedPlatformNamesForID(id string) []string {
	policies := ReviewedPlatformsForID(id)
	result := make([]string, 0, len(policies))
	for _, policy := range policies {
		result = append(result, policy.DisplayName)
	}
	return result
}

// LibcSupported is intentionally a no-op for platforms whose reviewed policy
// does not distinguish libc. Void is currently the only supported target with
// an explicit runtime libc choice.
func LibcSupported(os OS, libc string) bool {
	policy, ok := PlatformPolicyFor(os)
	if !ok {
		return false
	}
	return len(policy.Libcs) == 0 || policy.SupportsLibc(libc)
}

// MutationToolPolicy exposes bootstrap-only prerequisites without callers
// rediscovering platform families through ad-hoc switches.
func MutationToolPolicy(os OS) (required bool, remediation string) {
	policy, ok := PlatformPolicyFor(os)
	if !ok || !policy.RequiresMutationTools {
		return false, ""
	}
	return true, policy.ManualToolRemediation
}

func platformFamily(id string) string {
	for _, policy := range platformPolicies {
		if policy.Match.ID == id {
			return policy.Family
		}
	}
	return "unsupported"
}

// RequiredCapabilities returns a stable copy used by policy contract tests.
func RequiredCapabilities() []Capability { return append([]Capability(nil), requiredCapabilities...) }
