package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestCreateRecoversRunningServiceAfterCaptureFailure(t *testing.T) {
	repository, cfg, deployment, _ := restoreFixture(t)
	host := restoreHost(deployment)
	host.Services[0] = facts.Service{Name: deployment.Name, Project: deployment.Project, DesiredState: "running", Runtime: "running", DeploymentPresent: true}
	fake := &createTransport{streamErr: errors.New("stream interrupted")}
	_, err := Create(context.Background(), repository, CreateRequest{Target: "local", Host: host, Config: cfg, Service: deployment.Name, Transport: fake})
	if err == nil || !strings.Contains(err.Error(), "stream interrupted") {
		t.Fatalf("backup failure was not reported: %v", err)
	}
	if !fake.called(" stop") || !fake.called("up -d --remove-orphans") {
		t.Fatalf("running service was not stopped and recovered: %q", fake.scripts)
	}
	listed, listErr := repository.List()
	if listErr != nil || len(listed) != 1 {
		t.Fatalf("failed capture published a snapshot: %#v %v", listed, listErr)
	}
}

func TestCreatePreservesStoppedServiceState(t *testing.T) {
	repository, cfg, deployment, _ := restoreFixture(t)
	host := restoreHost(deployment)
	host.Services[0] = facts.Service{Name: deployment.Name, Project: deployment.Project, DesiredState: "stopped", Runtime: "stopped", DeploymentPresent: true}
	fake := &createTransport{archive: tarFixture(t, "state", "portable")}
	result, err := Create(context.Background(), repository, CreateRequest{Target: "local", Host: host, Config: cfg, Service: deployment.Name, Transport: fake})
	if err != nil {
		t.Fatal(err)
	}
	if result.Snapshot.SnapshotID == "" {
		t.Fatal("stopped service backup did not complete")
	}
	if fake.called(" stop") || fake.called("up -d --remove-orphans") {
		t.Fatalf("backup changed stopped service runtime state: %q", fake.scripts)
	}
}

func TestCreateBlocksStorageRelativePathWithoutReadyPlacement(t *testing.T) {
	repository, cfg, deployment, _ := storageRestoreFixture(t)
	host := restoreHost(deployment)
	host.Storage = facts.Storage{Available: true, Mounts: []facts.StorageMount{{Target: "/", UUID: "root"}}}
	fake := &createTransport{archive: tarFixture(t, "state", "portable")}
	_, err := Create(context.Background(), repository, CreateRequest{Target: "local", Host: host, Config: cfg, Service: deployment.Name, Transport: fake})
	if err == nil {
		t.Fatal("backup accepted a root-spill storage-relative path")
	}
	var categorized *errs.Error
	if !errorsAs(err, &categorized) || categorized.Code != errs.PlanBlocked {
		t.Fatalf("storage placement failure lost plan-blocked category: %v", err)
	}
	if fake.streamCalls != 0 {
		t.Fatalf("backup streamed data after placement validation failed: %d", fake.streamCalls)
	}
}

type createTransport struct {
	scripts     []string
	streamErr   error
	archive     []byte
	streamCalls int
}

func (tr *createTransport) Description() string                              { return "create fake" }
func (tr *createTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (tr *createTransport) FileExists(context.Context, string) (bool, error) { return false, nil }

func (tr *createTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	tr.scripts = append(tr.scripts, request.Script)
	switch {
	case strings.Contains(request.Script, "docker --context default ps --all --quiet"):
		return transport.Result{Stdout: "container-id\n"}, nil
	case strings.Contains(request.Script, "docker --context default inspect --format"):
		return transport.Result{Stdout: `{"Status":"running","Running":true}`}, nil
	default:
		return transport.Result{}, nil
	}
}

func (tr *createTransport) RunStream(_ context.Context, request transport.StreamRequest, output io.Writer) (transport.Result, error) {
	tr.streamCalls++
	if tr.streamErr != nil {
		return transport.Result{}, tr.streamErr
	}
	_, err := output.Write(tr.archive)
	return transport.Result{}, err
}

func (tr *createTransport) AcquireApplyLock(context.Context) (transport.ApplyLock, error) {
	return testLock{}, nil
}

func (tr *createTransport) called(fragment string) bool {
	for _, script := range tr.scripts {
		if strings.Contains(script, fragment) {
			return true
		}
	}
	return false
}

func tarFixture(t *testing.T, name, contents string) []byte {
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
	return output.Bytes()
}
