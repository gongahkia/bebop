package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"

	"github.com/bebop-home/bebop/internal/buildinfo"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/transport"
)

// HelperImage is an implementation detail, not a user-configurable workload.
// This stable BusyBox release publishes linux/amd64 and linux/arm64 images.
// Docker may pull it once if the target is online and it is not already cached.
const HelperImage = "busybox:1.36.1"

type CreateRequest struct {
	HostAlias string
	Target    string
	Host      facts.HostFacts
	Config    config.Config
	Service   string
	Transport transport.Transport
}

type CreateResult struct {
	Snapshot Manifest `json:"snapshot"`
	Services []string `json:"services"`
}

// Create produces a new immutable full snapshot. It uses the ordinary target
// apply lock because stop-consistent captures intentionally change runtime
// state. Completion is never reported until the manifest and every archive
// have been re-verified locally and stopped services are healthy again.
func Create(ctx context.Context, repository Repository, request CreateRequest) (result CreateResult, resultErr error) {
	if request.Transport == nil {
		return result, fmt.Errorf("backup requires a target transport")
	}
	streamer, supported := request.Transport.(transport.StreamTransport)
	if !supported {
		return result, fmt.Errorf("target transport does not support streaming backup archives")
	}
	if !request.Host.Docker.Responsive || !request.Host.Docker.ComposeAvailable {
		return result, errs.New(errs.PlanBlocked, "backup requires a responsive Docker Engine and Docker Compose v2", nil)
	}
	deployments, err := services.ResolveAll(request.Config)
	if err != nil {
		return result, err
	}
	selected, err := selectDeployments(deployments, request.Service)
	if err != nil {
		return result, err
	}
	locker, supportsLock := request.Transport.(transport.ApplyLocker)
	if !supportsLock {
		return result, errs.New(errs.ApplyLocked, "backup requires a transport with the Bebop target apply lock", nil)
	}
	lock, err := locker.AcquireApplyLock(ctx)
	if err != nil {
		return result, classifyLock(err)
	}
	defer lock.Release()
	if err := ensureHelper(ctx, request.Transport); err != nil {
		return result, errs.New(errs.PlanBlocked, "backup helper image is unavailable", err)
	}

	stage, err := repository.Begin(Source{HostAlias: request.HostAlias, Target: request.Target, Identity: request.Host.Identity(), OS: request.Host.OS, Architecture: request.Host.Architecture}, buildinfo.Version)
	if err != nil {
		return result, err
	}
	completed := false
	defer func() {
		if !completed {
			_ = stage.Abort()
		}
	}()

	for _, deployment := range selected {
		fact := serviceFact(request.Host, deployment.Name)
		if deployment.State == "absent" {
			return result, errs.New(errs.PlanBlocked, "cannot back up absent service "+deployment.Name, nil)
		}
		for _, resource := range deployment.Data {
			if err := validateSourceResource(ctx, request.Transport, deployment, resource); err != nil {
				return result, errs.New(errs.PlanBlocked, "backup resource "+deployment.Name+"/"+resource.Name+" is not ready", err)
			}
		}

		stopped := false
		if deployment.BackupConsistency == "stop" && serviceIsRunning(fact) {
			if _, err := request.Transport.Run(ctx, transport.Request{Script: modules.ComposeCommand(request.Config.Storage.DataRoot, deployment, "stop"), Privileged: true}); err != nil {
				return result, fmt.Errorf("stop service %s for consistent backup: %w", deployment.Name, err)
			}
			stopped = true
		}
		configurationDigest, err := ServiceConfigurationDigest(deployment)
		if err != nil {
			return result, err
		}
		serviceManifest := ServiceManifest{Name: deployment.Name, ConfigurationDigest: configurationDigest, DeploymentDigest: fact.DeploymentDigest, Consistency: deployment.BackupConsistency}
		backupErr := func() error {
			for _, resource := range deployment.Data {
				captured, err := capture(ctx, stage, streamer, deployment, resource)
				if err != nil {
					return err
				}
				serviceManifest.Resources = append(serviceManifest.Resources, captured)
			}
			return stage.AddService(serviceManifest)
		}()
		if stopped {
			restartErr := restartAndVerify(ctx, request.Transport, request.Config, deployment)
			if backupErr != nil && restartErr != nil {
				return result, fmt.Errorf("backup service %s: %v; recovery restart also failed: %w", deployment.Name, backupErr, restartErr)
			}
			if restartErr != nil {
				return result, fmt.Errorf("backup service %s succeeded but recovery restart failed: %w", deployment.Name, restartErr)
			}
		}
		if backupErr != nil {
			return result, backupErr
		}
		result.Services = append(result.Services, deployment.Name)
	}
	manifest, err := stage.Complete()
	if err != nil {
		return result, errs.New(errs.VerificationFailed, "verify completed backup snapshot", err)
	}
	completed = true
	result.Snapshot = manifest
	return result, nil
}

func selectDeployments(all []services.Deployment, name string) ([]services.Deployment, error) {
	selected := make([]services.Deployment, 0, len(all))
	for _, deployment := range all {
		if name != "" && deployment.Name != name {
			continue
		}
		if len(deployment.Data) > 0 {
			selected = append(selected, deployment)
		}
	}
	if name != "" && len(selected) == 0 {
		return nil, errs.New(errs.ConfigInvalid, "service "+name+" has no declared persistent data", nil)
	}
	if len(selected) == 0 {
		return nil, errs.New(errs.ConfigInvalid, "no services declare persistent data for backup", nil)
	}
	return selected, nil
}

func capture(ctx context.Context, stage *Stage, streamer transport.StreamTransport, deployment services.Deployment, resource services.PersistentResource) (ResourceManifest, error) {
	reader, writer := io.Pipe()
	type captureResult struct {
		manifest ResourceManifest
		err      error
	}
	done := make(chan captureResult, 1)
	archiveName := path.Join("services", deployment.Name, "data", resource.Name+".tar")
	go func() {
		manifest, err := stage.WriteArchive(ctx, archiveName, reader)
		_ = reader.CloseWithError(err)
		done <- captureResult{manifest: manifest, err: err}
	}()
	_, streamErr := streamer.RunStream(ctx, transport.StreamRequest{Script: backupArchiveScript(resource), Privileged: true}, writer)
	_ = writer.CloseWithError(streamErr)
	captured := <-done
	if streamErr != nil {
		return ResourceManifest{}, fmt.Errorf("stream %s from %s: %w", resource.Name, ResourceLabel(resource), streamErr)
	}
	if captured.err != nil {
		return ResourceManifest{}, fmt.Errorf("sanitize %s archive: %w", resource.Name, captured.err)
	}
	captured.manifest.Name, captured.manifest.Type = resource.Name, resource.Type
	return captured.manifest, nil
}

func ensureHelper(ctx context.Context, tr transport.Transport) error {
	_, err := tr.Run(ctx, transport.Request{Script: dockerPrefix() + " image inspect " + transport.ShellQuote(HelperImage) + " >/dev/null 2>&1 || " + dockerPrefix() + " pull " + transport.ShellQuote(HelperImage), Privileged: true})
	return err
}

func validateSourceResource(ctx context.Context, tr transport.Transport, deployment services.Deployment, resource services.PersistentResource) error {
	switch resource.Type {
	case "volume":
		labels := dockerPrefix() + " volume inspect --format '{{ index .Labels \"com.docker.compose.project\" }}{{ printf \"\\t\" }}{{ index .Labels \"com.docker.compose.volume\" }}' " + transport.ShellQuote(resource.RuntimeVolume)
		script := dockerPrefix() + " volume inspect " + transport.ShellQuote(resource.RuntimeVolume) + " >/dev/null\n"
		if !resource.External {
			script += "actual=$(" + labels + ")\ntest \"$actual\" = " + transport.ShellQuote(deployment.Project+"\t"+resource.VolumeKey)
		}
		_, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
		return err
	case "path":
		script := "test -d " + transport.ShellQuote(resource.Path) + "\ntest ! -L " + transport.ShellQuote(resource.Path) + "\nactual=$(readlink -f -- " + transport.ShellQuote(resource.Path) + ")\ntest \"$actual\" = " + transport.ShellQuote(resource.Path)
		_, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
		return err
	default:
		return fmt.Errorf("unsupported persistent resource type %q", resource.Type)
	}
}

func backupArchiveScript(resource services.PersistentResource) string {
	mount := resource.RuntimeVolume + ":/data:ro"
	if resource.Type == "path" {
		mount = resource.Path + ":/data:ro"
	}
	return dockerPrefix() + " run --rm -i --network none --read-only -v " + transport.ShellQuote(mount) + " " + transport.ShellQuote(HelperImage) + " tar -C /data -cf - ."
}

func dockerPrefix() string {
	return "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default"
}

func restartAndVerify(ctx context.Context, tr transport.Transport, cfg config.Config, deployment services.Deployment) error {
	if _, err := tr.Run(ctx, transport.Request{Script: modules.ComposeCommand(cfg.Storage.DataRoot, deployment, "up -d --remove-orphans"), Privileged: true}); err != nil {
		return err
	}
	return (modules.Compose{}).Verify(ctx, tr, cfg, plan.Change{Module: "services", Action: plan.Action{Kind: "service.start", Resource: deployment.Name}})
}

func serviceFact(host facts.HostFacts, name string) facts.Service {
	for _, service := range host.Services {
		if service.Name == name {
			return service
		}
	}
	return facts.Service{Name: name, Runtime: "missing"}
}

func serviceIsRunning(service facts.Service) bool {
	return service.Runtime == "running" || service.Runtime == "starting"
}

func classifyLock(err error) error {
	var lockError *transport.LockError
	if errors.As(err, &lockError) && lockError.Busy {
		return errs.New(errs.ApplyLocked, lockError.Error(), err)
	}
	return errs.New(errs.ApplyLocked, "acquire target apply lock for backup", err)
}

func ResourceLabel(resource services.PersistentResource) string {
	if resource.Type == "volume" {
		return "named volume " + resource.RuntimeVolume
	}
	return "bind path " + resource.Path
}

// ServiceConfigurationDigest deliberately omits host-local server identity and
// runtime volume names. It binds a snapshot to the portable service source and
// logical persistent-resource declarations, not source-host implementation
// details that legitimately differ on migration.
func ServiceConfigurationDigest(deployment services.Deployment) (string, error) {
	semantic := struct {
		Name        string                        `json:"name"`
		Source      string                        `json:"source"`
		Data        []services.PersistentResource `json:"data"`
		Consistency string                        `json:"consistency"`
	}{Name: deployment.Name, Source: deployment.SourceDigest, Data: append([]services.PersistentResource(nil), deployment.Data...), Consistency: deployment.BackupConsistency}
	for index := range semantic.Data {
		semantic.Data[index].RuntimeVolume = ""
		semantic.Data[index].Path = "" // resource path is target-local, logical name/type is portable.
	}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
