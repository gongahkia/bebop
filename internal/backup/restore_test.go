package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestRestorePlanIsCanonicalTamperAwareAndDetectsDestinationDrift(t *testing.T) {
	repository, cfg, deployment, manifest := restoreFixture(t)
	host := restoreHost(deployment)
	fake := &restoreTransport{}
	request := RestoreRequest{SnapshotID: manifest.SnapshotID, Target: "local", Config: cfg, Host: host, Service: "hello", Transport: fake}
	first, err := BuildRestorePlan(context.Background(), repository, request)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildRestorePlan(context.Background(), repository, request)
	if err != nil || first.Fingerprint != second.Fingerprint {
		t.Fatalf("restore plan was not deterministic: %#v %#v %v", first, second, err)
	}
	filename := filepath.Join(t.TempDir(), "restore.json")
	if err := WriteRestorePlan(filename, first); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRestorePlan(filename); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(contents), `"destination_fingerprint":`, `"destination_fingerprint":"tampered", "ignored":`, 1)
	if err := os.WriteFile(filename, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRestorePlan(filename); err == nil {
		t.Fatal("tampered restore plan was accepted")
	}

	fake.exists, fake.empty = true, false
	changed, err := BuildRestorePlan(context.Background(), repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Fingerprint == first.Fingerprint {
		t.Fatal("destination data drift did not stale restore plan")
	}
}

func TestRestoreBlocksNonEmptyDestinationAndWrongHost(t *testing.T) {
	repository, cfg, deployment, manifest := restoreFixture(t)
	host := restoreHost(deployment)
	fake := &restoreTransport{exists: true, empty: false}
	request := RestoreRequest{SnapshotID: manifest.SnapshotID, Target: "local", Config: cfg, Host: host, Service: "hello", Transport: fake}
	reviewed, err := BuildRestorePlan(context.Background(), repository, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRestore(context.Background(), repository, reviewed, request); err == nil || !strings.Contains(err.Error(), "already contains data") {
		t.Fatalf("non-empty destination was not blocked: %v", err)
	}
	wrong := request
	wrong.Host.MachineID = "different-host"
	if _, err := ApplyRestore(context.Background(), repository, reviewed, wrong); err == nil {
		t.Fatal("wrong-host restore was accepted")
	} else {
		var categorized *errs.Error
		if !errorsAs(err, &categorized) || categorized.Code != errs.TargetIdentityMismatch {
			t.Fatalf("wrong-host error lost category: %v", err)
		}
	}
}

func TestRestoreStoragePlacementAndCapacityAreRechecked(t *testing.T) {
	repository, cfg, deployment, manifest := storageRestoreFixture(t)
	host := restoreHost(deployment)
	host.Storage = readyStorage("bulk", 128<<20)
	fake := &restoreTransport{}
	request := RestoreRequest{SnapshotID: manifest.SnapshotID, Target: "local", Config: cfg, Host: host, Service: deployment.Name, Transport: fake}
	reviewed, err := BuildRestorePlan(context.Background(), repository, request)
	if err != nil {
		t.Fatal(err)
	}

	drifted := request
	drifted.Host.Storage = facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/", UUID: "root"}}}
	if _, err := ApplyRestore(context.Background(), repository, reviewed, drifted); err == nil {
		t.Fatal("restore accepted storage root-spill after review")
	} else {
		var categorized *errs.Error
		if !errorsAs(err, &categorized) || categorized.Code != errs.PlanStale {
			t.Fatalf("storage placement drift lost stale-plan category: %v", err)
		}
	}

	tooSmall := request
	tooSmall.Host.Storage = readyStorage("bulk", 1)
	if _, err := BuildRestorePlan(context.Background(), repository, tooSmall); err == nil {
		t.Fatal("restore plan accepted insufficient destination capacity")
	} else {
		var categorized *errs.Error
		if !errorsAs(err, &categorized) || categorized.Code != errs.PlanBlocked {
			t.Fatalf("capacity preflight lost plan-blocked category: %v", err)
		}
	}
}

func TestRestoreMapsLogicalDataToDifferentlyNamedDestinationStorage(t *testing.T) {
	repository, sourceConfig, sourceDeployment, manifest := storageRestoreFixture(t)
	destinationConfig := sourceConfig
	destinationConfig.Storage.Resources = []config.StorageResource{{Name: "archive", Mount: "/mnt/archive", FilesystemUUID: "22222222-3333-4444-5555-666666666666", FilesystemType: "ext4"}}
	destinationConfig.Services[0].Data[0].Storage = "archive"
	destinationDeployment, err := services.ResolveOne(destinationConfig, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if destinationDeployment.SourceDigest != sourceDeployment.SourceDigest {
		t.Fatal("portable data interpolation changed Compose source identity")
	}
	destinationHost := restoreHost(destinationDeployment)
	destinationHost.MachineID = "different-destination"
	destinationHost.Storage = facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/mnt/archive", UUID: "22222222-3333-4444-5555-666666666666", Filesystem: "ext4", SizeBytes: 256 << 20, AvailableBytes: 128 << 20}}}
	plan, err := BuildRestorePlan(context.Background(), repository, RestoreRequest{SnapshotID: manifest.SnapshotID, Target: "destination", Config: destinationConfig, Host: destinationHost, Service: "hello", Transport: &restoreTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Services[0].Resources[0].Destination != "/mnt/archive/state" {
		t.Fatalf("logical resource did not map to destination storage: %#v", plan.Services)
	}
}

func restoreFixture(t *testing.T) (Repository, config.Config, services.Deployment, Manifest) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte(`services:
  hello:
    image: alpine:3.20
    volumes: [data:/data]
volumes:
  data: {}
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(`version = 1
[backup]
destination = "backups"
[services.hello]
type = "compose"
source = "services/hello"
[[services.hello.data]]
name = "app-data"
type = "volume"
volume = "data"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := repository.Begin(Source{Target: "local", Identity: facts.Identity{MachineID: "source"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := stage.WriteArchive(context.Background(), "services/hello/data/app-data.tar", simpleArchive(t, "state", "portable"))
	if err != nil {
		t.Fatal(err)
	}
	resource.Name, resource.Type = "app-data", "volume"
	digest, err := ServiceConfigurationDigest(deployment)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.AddService(ServiceManifest{Name: "hello", ConfigurationDigest: digest, Consistency: "stop", Resources: []ResourceManifest{resource}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := stage.Complete()
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
	return repository, cfg, deployment, manifest
}

func storageRestoreFixture(t *testing.T) (Repository, config.Config, services.Deployment, Manifest) {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte(`services:
  hello:
    image: alpine:3.20
    volumes: ["${BEBOP_DATA_APP_DATA}:/data"]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(`version = 1
[backup]
destination = "backups"
[storage.resources.bulk]
mount = "/mnt/bulk"
filesystem_uuid = "11111111-2222-3333-4444-555555555555"
filesystem_type = "ext4"
[services.hello]
type = "compose"
source = "services/hello"
[[services.hello.data]]
name = "app-data"
type = "path"
path = "state"
storage = "bulk"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := services.ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := repository.Begin(Source{Target: "local", Identity: facts.Identity{MachineID: "source"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := stage.WriteArchive(context.Background(), "services/hello/data/app-data.tar", simpleArchive(t, "state", "portable"))
	if err != nil {
		t.Fatal(err)
	}
	resource.Name, resource.Type = "app-data", "path"
	digest, err := ServiceConfigurationDigest(deployment)
	if err != nil {
		t.Fatal(err)
	}
	if err := stage.AddService(ServiceManifest{Name: "hello", ConfigurationDigest: digest, Consistency: "stop", Resources: []ResourceManifest{resource}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := stage.Complete()
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
	return repository, cfg, deployment, manifest
}

func readyStorage(name string, available int64) facts.Storage {
	return facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/mnt/" + name, UUID: "11111111-2222-3333-4444-555555555555", Filesystem: "ext4", SizeBytes: 8 << 20, AvailableBytes: available}}}
}

func restoreHost(deployment services.Deployment) facts.HostFacts {
	return facts.HostFacts{Target: "local", MachineID: "destination", OS: facts.OS{ID: "debian", Supported: true}, Architecture: "amd64", Docker: facts.Docker{Responsive: true, ComposeAvailable: true}, Services: []facts.Service{{Name: deployment.Name, Project: deployment.Project, DesiredState: "running", Runtime: "missing"}}}
}

func simpleArchive(t *testing.T, name, contents string) io.Reader {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(contents))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(output.Bytes())
}

type restoreTransport struct{ exists, empty bool }

func (tr *restoreTransport) Description() string                              { return "restore fake" }
func (tr *restoreTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (tr *restoreTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (tr *restoreTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	switch {
	case strings.Contains(request.Script, "printf exists=yes"):
		if tr.exists {
			return transport.Result{Stdout: "exists=yes\n"}, nil
		}
		return transport.Result{Stdout: "exists=no\n"}, nil
	case strings.Contains(request.Script, "find \"$mountpoint\""):
		if tr.empty {
			return transport.Result{Stdout: "empty=yes"}, nil
		}
		return transport.Result{Stdout: "empty=no"}, nil
	case strings.Contains(request.Script, "image inspect"):
		return transport.Result{}, nil
	default:
		return transport.Result{}, nil
	}
}
func (tr *restoreTransport) RunStream(_ context.Context, request transport.StreamRequest, output io.Writer) (transport.Result, error) {
	if request.Stdin != nil {
		_, _ = io.Copy(output, request.Stdin)
	}
	return transport.Result{}, nil
}
func (*restoreTransport) AcquireApplyLock(context.Context) (transport.ApplyLock, error) {
	return testLock{}, nil
}

type testLock struct{}

func (testLock) Release() error { return nil }

func errorsAs(err error, target **errs.Error) bool {
	for err != nil {
		if value, ok := err.(*errs.Error); ok {
			*target = value
			return true
		}
		type unwrap interface{ Unwrap() error }
		value, ok := err.(unwrap)
		if !ok {
			return false
		}
		err = value.Unwrap()
	}
	return false
}
