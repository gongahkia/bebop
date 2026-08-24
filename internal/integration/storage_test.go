//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/backup"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/services"
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

// TestStoragePlacementMigrationAgainstDisposableDind proves the M4+M6
// composition with real target filesystems. The same portable data resource is
// backed up from source storage "fast" and restored to destination storage
// "bulk"; the Compose source remains identical because it interpolates the
// logical data name rather than either host-local storage name.
func TestStoragePlacementMigrationAgainstDisposableDind(t *testing.T) {
	if testing.Short() || os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	source, destination := startDind(t), startDind(t)
	sourceUUID := prepareStorageImage(t, source, "/tmp/source-storage.img", "/mnt/fast")
	destinationUUID := prepareStorageImage(t, destination, "/tmp/destination-storage.img", "/mnt/bulk")
	sourceRoot, destinationRoot := t.TempDir(), t.TempDir()
	writeStorageComposeFixture(t, sourceRoot, "storage-source", "fast", "/mnt/fast", sourceUUID)
	writeStorageComposeFixture(t, destinationRoot, "storage-destination", "bulk", "/mnt/bulk", destinationUUID)
	sourceConfig, destinationConfig := loadComposeFixture(t, sourceRoot), loadComposeFixture(t, destinationRoot)
	sourceConfig.Backup.Destination = filepath.Join(t.TempDir(), "backups")
	provider := modules.Compose{PollInterval: 50 * time.Millisecond}
	sourceDeployment, err := services.ResolveOne(sourceConfig, "hello")
	if err != nil {
		t.Fatal(err)
	}
	destinationDeployment, err := services.ResolveOne(destinationConfig, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if sourceDeployment.SourceDigest != destinationDeployment.SourceDigest {
		t.Fatal("host-local storage names changed portable Compose source identity")
	}
	sourceHost := storageDindHost(sourceConfig, sourceDeployment, "storage-source-id", "/mnt/fast", sourceUUID)
	runServiceChanges(t, provider, source, sourceConfig, buildPlan(t, planner.New(provider), sourceHost, sourceConfig))
	assertExec(t, source, "printf '%s\\n' BEBOP_M6_PORTABLE_STATE > /mnt/fast/app-data/state")
	sourceHost.Services[0] = facts.Service{Name: "hello", Project: sourceDeployment.Project, DesiredState: "running", DeploymentPresent: true, DeploymentDigest: sourceDeployment.SourceDigest, Runtime: "running", Health: "healthy"}
	repository, err := backup.Open(sourceConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(repository.Root(), func(filename string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(filename, 0o700)
			}
			return nil
		})
	})
	snapshot, err := backup.Create(context.Background(), repository, backup.CreateRequest{HostAlias: "source", Target: "dind-source", Host: sourceHost, Config: sourceConfig, Service: "hello", Transport: source})
	if err != nil {
		t.Fatal(err)
	}
	destinationHost := storageDindHost(destinationConfig, destinationDeployment, "storage-destination-id", "/mnt/bulk", destinationUUID)
	restoreRequest := backup.RestoreRequest{SnapshotID: snapshot.Snapshot.SnapshotID, HostAlias: "destination", Target: "dind-destination", Config: destinationConfig, Host: destinationHost, Service: "hello", Transport: destination}
	restorePlan, err := backup.BuildRestorePlan(context.Background(), repository, restoreRequest)
	if err != nil {
		t.Fatal(err)
	}
	if restorePlan.Services[0].Resources[0].Destination != "/mnt/bulk/app-data" {
		t.Fatalf("restore did not use destination storage mapping: %#v", restorePlan.Services)
	}
	if _, err := backup.ApplyRestore(context.Background(), repository, restorePlan, restoreRequest); err != nil {
		t.Fatal(err)
	}
	assertExec(t, destination, "grep -qx BEBOP_M6_PORTABLE_STATE /mnt/bulk/app-data/state")
	runServiceChanges(t, provider, destination, destinationConfig, buildPlan(t, planner.New(provider), destinationHost, destinationConfig))
	assertExec(t, destination, "grep -qx BEBOP_M6_PORTABLE_STATE /mnt/bulk/app-data/state")
}

func prepareStorageImage(t *testing.T, target *dockerExecTransport, image, mount string) string {
	t.Helper()
	if _, err := target.Run(context.Background(), transportRequest("apk add --no-cache e2fsprogs util-linux >/dev/null && truncate -s 128M "+shellQuote(image)+" && mkfs.ext4 -F "+shellQuote(image)+" >/dev/null && mkdir -p "+shellQuote(mount)+" && mount -o loop "+shellQuote(image)+" "+shellQuote(mount))); err != nil {
		t.Skipf("disposable target cannot prepare loop-backed storage image: %v", err)
	}
	result, err := target.Run(context.Background(), transportRequest("blkid -s UUID -o value "+shellQuote(image)))
	if err != nil || strings.TrimSpace(result.Stdout) == "" {
		t.Skipf("could not inspect disposable storage UUID: %v", err)
	}
	return strings.TrimSpace(result.Stdout)
}

func writeStorageComposeFixture(t *testing.T, root, server, storageName, mount, uuid string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := `services:
  hello:
    image: busybox:1.36.1
    command: ["sh", "-c", "touch /tmp/ready; sleep 600"]
    healthcheck:
      test: ["CMD-SHELL", "test -f /tmp/ready"]
      interval: 1s
      timeout: 1s
      retries: 3
    volumes:
      - type: bind
        source: ${BEBOP_DATA_APP_DATA}
        target: /data
`
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	contents := `version = 1
[server]
name = "` + server + `"
[storage]
data_root = "/work/bebop"
[storage.resources.` + storageName + `]
mount = "` + mount + `"
filesystem_uuid = "` + uuid + `"
filesystem_type = "ext4"
[services.hello]
type = "compose"
source = "services/hello"
state = "running"
health_timeout = "30s"
[[services.hello.data]]
name = "app-data"
type = "path"
storage = "` + storageName + `"
path = "app-data"
[services.hello.backup]
consistency = "stop"
`
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func storageDindHost(cfg config.Config, deployment services.Deployment, machineID, mount, uuid string) facts.HostFacts {
	host := dindHost(cfg, facts.Service{Name: deployment.Name, Project: deployment.Project, DesiredState: "running", Runtime: "missing", Health: "missing"})
	host.MachineID = machineID
	host.Storage = facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: mount, UUID: uuid, Filesystem: "ext4", SizeBytes: 128 << 20, AvailableBytes: 96 << 20}}}
	return host
}
