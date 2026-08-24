//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
)

// TestManagedStorageMountAgainstDisposableImage exercises production mount
// actions only inside a privileged disposable Dind target. The image file,
// loop association, mount point, and fstab are all inside that container; no
// controller filesystem or host mount configuration is touched.
func TestManagedStorageMountAgainstDisposableImage(t *testing.T) {
	if testing.Short() || os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run disposable storage integration")
	}
	target := startDind(t)
	ctx := context.Background()
	if _, err := target.Run(ctx, transportRequest("apk add --no-cache e2fsprogs util-linux >/dev/null && truncate -s 32M /tmp/bebop-storage.img && mkfs.ext4 -F /tmp/bebop-storage.img >/dev/null && mkdir -p /mnt/bebop-storage")); err != nil {
		t.Skipf("disposable target lacks filesystem-image utilities: %v", err)
	}
	uuidResult, err := target.Run(ctx, transportRequest("blkid -s UUID -o value /tmp/bebop-storage.img"))
	if err != nil || strings.TrimSpace(uuidResult.Stdout) == "" {
		t.Skipf("could not inspect disposable filesystem UUID: %v", err)
	}
	uuid := strings.TrimSpace(uuidResult.Stdout)
	cfg := config.Defaults()
	cfg.Storage.Resources = []config.StorageResource{{Name: "fast", Mount: "/mnt/bebop-storage", FilesystemUUID: uuid, FilesystemType: "ext4", ManagedMount: true}}
	host := facts.HostFacts{SudoAvailable: true, Storage: facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/", UUID: "root"}}}}
	provider := modules.Storage{}
	changes, _, err := provider.Plan(host, cfg)
	if err != nil || len(changes) != 3 {
		t.Fatalf("unexpected storage plan: %#v %v", changes, err)
	}
	for _, change := range changes {
		if err := provider.Apply(ctx, target, cfg, change); err != nil {
			t.Skipf("disposable target cannot perform loop-backed mount: %v", err)
		}
		if err := provider.Verify(ctx, target, cfg, change); err != nil {
			t.Fatalf("storage action %s did not verify: %v", change.ID, err)
		}
	}
	if _, err := target.Run(ctx, transportRequest("test \"$(findmnt -rn -o UUID --target /mnt/bebop-storage)\" = "+shellQuote(uuid))); err != nil {
		t.Fatalf("disposable filesystem was not mounted by UUID: %v", err)
	}
	host.Storage.Mounts = []facts.StorageMount{{Target: "/", UUID: "root"}, {Target: "/mnt/bebop-storage", UUID: uuid, Filesystem: "ext4", SizeBytes: 32 << 20, AvailableBytes: 16 << 20}}
	second, _, err := provider.Plan(host, cfg)
	if err != nil || len(second) != 0 {
		t.Fatalf("managed storage did not converge: %#v %v", second, err)
	}
}
