package storage

import (
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
)

func TestAssessDistinguishesRootSpillAndReady(t *testing.T) {
	resource := config.StorageResource{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", FilesystemType: "ext4", MinimumCapacityBytes: 100, MinimumFreeBytes: 10}
	rootOnly := facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/", Source: "/dev/vda1", UUID: "root", Filesystem: "ext4"}}}
	if assessment := Assess(resource, rootOnly); assessment.State != RootSpill {
		t.Fatalf("state = %s, want root spill", assessment.State)
	}
	ready := facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/mnt/bulk", Source: "/dev/vdb1", UUID: resource.FilesystemUUID, Filesystem: "ext4", SizeBytes: 200, AvailableBytes: 50}}}
	if assessment := Assess(resource, ready); assessment.State != Ready {
		t.Fatalf("state = %s, want ready (%s)", assessment.State, assessment.Detail)
	}
}

func TestAssessRejectsSemanticPlacementFailures(t *testing.T) {
	resource := config.StorageResource{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", FilesystemType: "ext4", MinimumCapacityBytes: 100, MinimumFreeBytes: 10}
	base := facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: resource.Mount, UUID: resource.FilesystemUUID, Filesystem: "ext4", SizeBytes: 200, AvailableBytes: 50}}}
	cases := []struct {
		name  string
		alter func(*facts.StorageMount)
		want  State
	}{
		{"uuid", func(m *facts.StorageMount) { m.UUID = "other" }, WrongUUID},
		{"type", func(m *facts.StorageMount) { m.Filesystem = "xfs" }, WrongType},
		{"readonly", func(m *facts.StorageMount) { m.ReadOnly = true }, ReadOnly},
		{"capacity", func(m *facts.StorageMount) { m.SizeBytes = 90 }, CapacityLow},
		{"free", func(m *facts.StorageMount) { m.AvailableBytes = 9 }, FreeSpaceLow},
		{"unsupported filesystem", func(m *facts.StorageMount) { m.Filesystem = "fuse" }, UnsupportedFilesystem},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			topology := base
			topology.Mounts = append([]facts.StorageMount(nil), base.Mounts...)
			test.alter(&topology.Mounts[0])
			if got := Assess(resource, topology).State; got != test.want {
				t.Fatalf("state = %s, want %s", got, test.want)
			}
		})
	}
}

func TestAssessRequiresCapacityFactsWhenThresholdConfigured(t *testing.T) {
	resource := config.StorageResource{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", MinimumFreeBytes: 1}
	topology := facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: resource.Mount, UUID: resource.FilesystemUUID, Filesystem: "ext4"}}}
	if got := Assess(resource, topology).State; got != FreeSpaceLow {
		t.Fatalf("state = %s, want %s", got, FreeSpaceLow)
	}
}

func TestAssessConflictingManagedMountConfigurationBlocksEvenWhenMounted(t *testing.T) {
	resource := config.StorageResource{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", ManagedMount: true}
	topology := facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: resource.Mount, UUID: resource.FilesystemUUID, Filesystem: "ext4"}}, MountConfigs: []facts.StorageMountConfig{{Name: resource.Name, State: "conflict"}}}
	if got := Assess(resource, topology).State; got != ConfigConflict {
		t.Fatalf("state = %s, want %s", got, ConfigConflict)
	}
	topology.MountConfigs[0].State = "external"
	if got := Assess(resource, topology).State; got != Ready {
		t.Fatalf("equivalent external mount config state = %s, want %s", got, Ready)
	}
}

func TestMountConfigProbeIsNarrowAndClassifiesUnknownOutput(t *testing.T) {
	resource := config.StorageResource{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", FilesystemType: "ext4"}
	probe := MountConfigProbe(resource)
	for _, required := range []string{"/etc/fstab", "UUID=11111111-2222-3333-4444-555555555555", "/mnt/bulk", "conflict", "external"} {
		if !strings.Contains(probe, required) {
			t.Fatalf("mount config probe lacks %q:\n%s", required, probe)
		}
	}
	if got := MountConfigState(resource, "unexpected"); got != "unknown" {
		t.Fatalf("state = %q, want unknown", got)
	}
}

func TestValidateResolvedPlacementStaysWithinMount(t *testing.T) {
	resource := config.StorageResource{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}
	storage := config.Storage{Resources: []config.StorageResource{resource}}
	host := facts.HostFacts{Storage: facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: resource.Mount, UUID: resource.FilesystemUUID, Filesystem: "ext4"}}}}
	if _, err := ValidateResolvedPlacement(storage, host, "bulk", "/mnt/bulk/media"); err != nil {
		t.Fatalf("valid placement: %v", err)
	}
	if _, err := ValidateResolvedPlacement(storage, host, "bulk", "/mnt/other/media"); err == nil {
		t.Fatal("escaped placement was accepted")
	}
}
