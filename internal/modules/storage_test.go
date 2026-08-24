package modules

import (
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
)

func TestStorageManagedMountPlansOrderedSafeActions(t *testing.T) {
	cfg := config.Defaults()
	cfg.Storage.Resources = []config.StorageResource{{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", FilesystemType: "ext4", ManagedMount: true}}
	host := facts.HostFacts{SudoAvailable: true, Storage: facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/", UUID: "root"}}}}
	changes, _, err := (Storage{}).Plan(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 3 || changes[2].ID != "storage.bulk.mount" || changes[2].Dependencies[0] != "storage.bulk.mount-config" {
		t.Fatalf("unexpected managed mount plan: %#v", changes)
	}
	if changes[0].Blocked != "" || changes[2].Action.Kind != "storage.mount" {
		t.Fatalf("managed mount was blocked or used wrong action: %#v", changes)
	}
}

func TestStorageWrongFilesystemBlocksWithoutMutation(t *testing.T) {
	cfg := config.Defaults()
	cfg.Storage.Resources = []config.StorageResource{{Name: "bulk", Mount: "/mnt/bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555", ManagedMount: true}}
	host := facts.HostFacts{SudoAvailable: true, Storage: facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/mnt/bulk", UUID: "other"}}}}
	changes, _, err := (Storage{}).Plan(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Action.Script != "" || changes[0].Blocked == "" {
		t.Fatalf("wrong filesystem must be visible but non-mutating: %#v", changes)
	}
}
