// Package storage owns storage-placement policy over normalized target facts.
// It intentionally has no disk provisioning API: M6 only recognizes an
// already-formatted filesystem by UUID and may mount it when explicitly
// authorized by configuration.
package storage

import (
	"fmt"
	"math"
	"path"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/transport"
)

type State string

const (
	Ready                 State = "ready"
	Unavailable           State = "unavailable"
	Missing               State = "missing"
	RootSpill             State = "root-spill"
	WrongUUID             State = "wrong-uuid"
	WrongType             State = "wrong-filesystem-type"
	ReadOnly              State = "read-only"
	CapacityLow           State = "capacity-low"
	FreeSpaceLow          State = "free-space-low"
	ConfigConflict        State = "conflicting-mount-config"
	ConfigUnknown         State = "mount-config-unknown"
	UnsupportedFilesystem State = "unsupported-filesystem"
)

type Assessment struct {
	Resource config.StorageResource `json:"resource"`
	State    State                  `json:"state"`
	Mount    facts.StorageMount     `json:"mount,omitempty"`
	Detail   string                 `json:"detail"`
}

func AssessAll(cfg config.Storage, topology facts.Storage) []Assessment {
	result := make([]Assessment, 0, len(cfg.Resources))
	for _, resource := range cfg.Resources {
		result = append(result, Assess(resource, topology))
	}
	return result
}

func Assess(resource config.StorageResource, topology facts.Storage) Assessment {
	result := Assessment{Resource: resource}
	if resource.ManagedMount {
		for _, mountConfig := range topology.MountConfigs {
			if mountConfig.Name != resource.Name {
				continue
			}
			switch mountConfig.State {
			case "conflict":
				result.State, result.Detail = ConfigConflict, "fstab has a conflicting mapping for the declared UUID or mount point"
				return result
			case "unknown":
				result.State, result.Detail = ConfigUnknown, "Bebop could not determine whether fstab conflicts with the declared mount"
				return result
			}
		}
	}
	if !topology.Available {
		result.State, result.Detail = Unavailable, "target did not provide usable lsblk and findmnt JSON storage facts"
		return result
	}
	var covering *facts.StorageMount
	for index := range topology.Mounts {
		mount := topology.Mounts[index]
		if mount.Target == resource.Mount {
			result.Mount = mount
			return assessMounted(result)
		}
		if mount.Target == "/" || strings.HasPrefix(resource.Mount, mount.Target+"/") {
			if covering == nil || len(mount.Target) > len(covering.Target) {
				candidate := mount
				covering = &candidate
			}
		}
	}
	if covering != nil {
		result.State, result.Mount, result.Detail = RootSpill, *covering, "configured mount point is currently served by "+covering.Target+" instead of its declared filesystem"
		return result
	}
	result.State, result.Detail = Missing, "configured filesystem is not mounted"
	return result
}

// MountConfigProbe classifies only the fstab entries that can affect one
// declared managed mount. It deliberately ignores unrelated entries and emits
// no potentially sensitive fstab contents. "external" is an equivalent
// user-owned UUID mapping that Bebop may use but does not rewrite.
func MountConfigProbe(resource config.StorageResource) string {
	mount := transport.ShellQuote(resource.Mount)
	source := transport.ShellQuote("UUID=" + resource.FilesystemUUID)
	filesystem := transport.ShellQuote(resource.FilesystemType)
	marker := transport.ShellQuote("# bebop-storage:" + resource.Name)
	return "mount=" + mount + "\nsource=" + source + "\nfilesystem=" + filesystem + "\nmarker=" + marker + `
if ! test -r /etc/fstab; then printf unknown; exit 0; fi
if grep -Fqx -- "$source $mount ${filesystem:-auto} defaults,nofail 0 2 $marker" /etc/fstab; then printf exact; exit 0; fi
awk -v mount="$mount" -v source="$source" -v filesystem="$filesystem" '
  NF && $1 !~ /^#/ {
    same_source = $1 == source
    same_mount = $2 == mount
    same_filesystem = filesystem == "" || $3 == filesystem || $3 == "auto"
    if (same_source && same_mount && same_filesystem) equivalent = 1
    else if (same_source || same_mount) conflict = 1
  }
  END {
    if (conflict) print "conflict"
    else if (equivalent) print "external"
    else print "absent"
  }
' /etc/fstab`
}

func MountConfigState(resource config.StorageResource, output string) string {
	state := strings.TrimSpace(output)
	switch state {
	case "exact", "external", "absent", "conflict":
		return state
	default:
		return "unknown"
	}
}

func assessMounted(result Assessment) Assessment {
	mount := result.Mount
	if mount.UUID == "" || mount.UUID != result.Resource.FilesystemUUID {
		result.State, result.Detail = WrongUUID, "mounted filesystem UUID does not match the declared storage resource"
		return result
	}
	if !placementFilesystemSupported(mount.Filesystem) {
		result.State, result.Detail = UnsupportedFilesystem, "mounted filesystem type is not supported for Bebop persistent-data placement"
		return result
	}
	if result.Resource.FilesystemType != "" && mount.Filesystem != result.Resource.FilesystemType {
		result.State, result.Detail = WrongType, "mounted filesystem type does not match the declared storage resource"
		return result
	}
	if mount.ReadOnly {
		result.State, result.Detail = ReadOnly, "mounted filesystem is read-only"
		return result
	}
	if result.Resource.MinimumCapacityBytes > 0 && mount.SizeBytes < result.Resource.MinimumCapacityBytes {
		result.State, result.Detail = CapacityLow, "mounted filesystem capacity is unavailable or below its configured capacity threshold"
		return result
	}
	if result.Resource.MinimumFreeBytes > 0 && mount.AvailableBytes < result.Resource.MinimumFreeBytes {
		result.State, result.Detail = FreeSpaceLow, "mounted filesystem free space is unavailable or below its configured free-space threshold"
		return result
	}
	result.State, result.Detail = Ready, "mounted filesystem identity and placement policy are satisfied"
	return result
}

func placementFilesystemSupported(filesystem string) bool {
	switch filesystem {
	case "ext2", "ext3", "ext4", "xfs", "btrfs":
		return true
	default:
		return false
	}
}

func Find(cfg config.Storage, name string) (config.StorageResource, bool) {
	for _, resource := range cfg.Resources {
		if resource.Name == name {
			return resource, true
		}
	}
	return config.StorageResource{}, false
}

func Placement(cfg config.Config, host facts.HostFacts, resource config.DataResource) (string, Assessment, error) {
	resolved, err := config.ResolveDataPath(cfg.Storage, resource)
	if err != nil {
		return "", Assessment{}, err
	}
	if resource.Storage == "" {
		return resolved, Assessment{State: Ready, Detail: "legacy explicit absolute bind path"}, nil
	}
	storageResource, found := Find(cfg.Storage, resource.Storage)
	if !found {
		return "", Assessment{}, fmt.Errorf("declared storage %q does not exist", resource.Storage)
	}
	assessment := Assess(storageResource, host.Storage)
	if assessment.State != Ready {
		return "", assessment, fmt.Errorf("storage %s is %s: %s", storageResource.Name, assessment.State, assessment.Detail)
	}
	if resolved == storageResource.Mount || !strings.HasPrefix(resolved, storageResource.Mount+"/") || path.Clean(resolved) != resolved {
		return "", assessment, fmt.Errorf("storage-relative path escapes its declared mount")
	}
	return resolved, assessment, nil
}

// ValidateResolvedPlacement is the target-side half of Placement for callers
// that already hold a services.PersistentResource. The resolved path must stay
// below the configured mount; no caller may turn an arbitrary absolute path
// into a storage-managed path by merely attaching a storage name.
func ValidateResolvedPlacement(cfg config.Storage, host facts.HostFacts, name, resolvedPath string) (Assessment, error) {
	resource, found := Find(cfg, name)
	if !found {
		return Assessment{}, fmt.Errorf("declared storage %q does not exist", name)
	}
	assessment := Assess(resource, host.Storage)
	if assessment.State != Ready {
		return assessment, fmt.Errorf("storage %s is %s: %s", resource.Name, assessment.State, assessment.Detail)
	}
	if resolvedPath == resource.Mount || !strings.HasPrefix(resolvedPath, resource.Mount+"/") || path.Clean(resolvedPath) != resolvedPath {
		return assessment, fmt.Errorf("storage-relative path escapes its declared mount")
	}
	return assessment, nil
}

// RequireFreeCapacity performs a conservative current-space check for an
// allocation operation such as restore. A zero/unknown available value is not
// treated as a guarantee; callers may proceed only when inspection supplied a
// positive value large enough for the known archive size.
func RequireFreeCapacity(assessment Assessment, bytes int64) error {
	if bytes <= 0 {
		return nil
	}
	if assessment.Mount.AvailableBytes <= 0 {
		return fmt.Errorf("available space for storage %s is unavailable", assessment.Resource.Name)
	}
	if assessment.Mount.AvailableBytes < bytes {
		return fmt.Errorf("storage %s has %d available bytes but restore requires at least %d bytes", assessment.Resource.Name, assessment.Mount.AvailableBytes, bytes)
	}
	return nil
}

// RestoreCapacityRequirement reserves modest filesystem metadata/headroom on
// top of a snapshot's logical archive size. It is deliberately a preflight
// safety estimate rather than a quota or a promise that concurrent writers
// cannot consume space after the check.
func RestoreCapacityRequirement(logicalBytes int64) (int64, error) {
	if logicalBytes < 0 {
		return 0, fmt.Errorf("restore size must not be negative")
	}
	if logicalBytes == 0 {
		return 0, nil
	}
	margin := logicalBytes / 20 // five percent
	if margin < 64<<20 {
		margin = 64 << 20
	}
	if logicalBytes > math.MaxInt64-margin {
		return 0, fmt.Errorf("restore size overflows capacity requirement")
	}
	return logicalBytes + margin, nil
}

// ReadyPrecondition narrows target fact inspection to mutation races. It
// checks the stable mount target/UUID/type and writeability, not volatile free
// space. Threshold capacity is rechecked by callers that make allocations.
func ReadyPrecondition(resource config.StorageResource) string {
	mount := transport.ShellQuote(resource.Mount)
	uuid := transport.ShellQuote(resource.FilesystemUUID)
	checks := []string{"test \"$(findmnt -rn -o TARGET --target " + mount + ")\" = " + mount, "test \"$(findmnt -rn -o UUID --target " + mount + ")\" = " + uuid, "test -w " + mount}
	if resource.FilesystemType != "" {
		checks = append(checks, "test \"$(findmnt -rn -o FSTYPE --target "+mount+")\" = "+transport.ShellQuote(resource.FilesystemType))
	}
	return strings.Join(checks, " && ")
}
