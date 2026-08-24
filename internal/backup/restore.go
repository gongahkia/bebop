package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bebop-home/bebop/internal/buildinfo"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/transport"
)

const RestorePlanSchemaVersion = 1

// RestorePlan is a destination-specific review artifact. It is separate from
// an immutable backup Manifest: a snapshot says what existed; this plan says
// exactly which empty destination resources Bebop is authorized to populate.
type RestorePlan struct {
	SchemaVersion          int              `json:"schema_version"`
	BebopVersion           string           `json:"bebop_version"`
	SnapshotID             string           `json:"snapshot_id"`
	SnapshotDigest         string           `json:"snapshot_digest"`
	ConfigPath             string           `json:"config_path,omitempty"`
	ConfigFingerprint      string           `json:"config_fingerprint"`
	Target                 string           `json:"target"`
	HostAlias              string           `json:"host_alias,omitempty"`
	TargetIdentity         facts.Identity   `json:"target_identity"`
	DestinationFingerprint string           `json:"destination_fingerprint"`
	Policy                 string           `json:"policy"`
	Services               []RestoreService `json:"services"`
	Warnings               []string         `json:"warnings,omitempty"`
	Fingerprint            string           `json:"fingerprint"`
}

type RestoreService struct {
	Name       string            `json:"name"`
	Runtime    string            `json:"runtime"`
	Deployment bool              `json:"deployment_present"`
	Resources  []RestoreResource `json:"resources"`
}

type RestoreResource struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Archive       string `json:"archive"`
	ArchiveSHA256 string `json:"archive_sha256"`
	StoredSize    int64  `json:"stored_size"`
	Destination   string `json:"destination"`
	Exists        bool   `json:"exists"`
	Empty         bool   `json:"empty"`
}

type RestoreRequest struct {
	SnapshotID string
	HostAlias  string
	Target     string
	ConfigPath string
	Config     config.Config
	Host       facts.HostFacts
	Service    string
	Transport  transport.Transport
}

type RestoreResult struct {
	Plan             RestorePlan `json:"plan"`
	Restored         []string    `json:"restored"`
	NeedsConvergence []string    `json:"needs_convergence,omitempty"`
}

func BuildRestorePlan(ctx context.Context, repository Repository, request RestoreRequest) (RestorePlan, error) {
	if request.Transport == nil {
		return RestorePlan{}, fmt.Errorf("restore planning requires a target transport")
	}
	manifest, err := repository.Verify(request.SnapshotID)
	if err != nil {
		return RestorePlan{}, err
	}
	configurationFingerprint, err := config.Fingerprint(request.Config)
	if err != nil {
		return RestorePlan{}, err
	}
	deployments, err := services.ResolveAll(request.Config)
	if err != nil {
		return RestorePlan{}, err
	}
	selected, err := restoreServices(manifest, deployments, request.Service)
	if err != nil {
		return RestorePlan{}, err
	}
	result := RestorePlan{SchemaVersion: RestorePlanSchemaVersion, BebopVersion: buildinfo.Version, SnapshotID: manifest.SnapshotID, SnapshotDigest: manifest.Digest, ConfigPath: request.ConfigPath, ConfigFingerprint: configurationFingerprint, Target: request.Target, HostAlias: request.HostAlias, TargetIdentity: request.Host.Identity(), Policy: "empty-only"}
	if manifest.Source.Architecture != "" && request.Host.Architecture != "" && manifest.Source.Architecture != request.Host.Architecture {
		result.Warnings = append(result.Warnings, "snapshot source architecture "+manifest.Source.Architecture+" differs from destination "+request.Host.Architecture+"; generic persistent data is normally portable, but container/application UID and format assumptions remain your responsibility")
	}
	for _, selectedService := range selected {
		fact := serviceFact(request.Host, selectedService.deployment.Name)
		service := RestoreService{Name: selectedService.deployment.Name, Runtime: fact.Runtime, Deployment: fact.DeploymentPresent}
		for _, sourceResource := range selectedService.snapshot.Resources {
			destination, found := persistentResource(selectedService.deployment, sourceResource.Name)
			if !found || destination.Type != sourceResource.Type {
				return RestorePlan{}, errs.New(errs.PlanBlocked, "destination service "+selectedService.deployment.Name+" does not declare compatible resource "+sourceResource.Name, nil)
			}
			state, err := destinationState(ctx, request.Transport, selectedService.deployment, destination)
			if err != nil {
				return RestorePlan{}, fmt.Errorf("inspect restore destination %s/%s: %w", service.Name, destination.Name, err)
			}
			service.Resources = append(service.Resources, RestoreResource{Name: sourceResource.Name, Type: sourceResource.Type, Archive: sourceResource.Archive, ArchiveSHA256: sourceResource.SHA256, StoredSize: sourceResource.StoredSize, Destination: state.destination, Exists: state.exists, Empty: state.empty})
		}
		sort.Slice(service.Resources, func(i, j int) bool { return service.Resources[i].Name < service.Resources[j].Name })
		result.Services = append(result.Services, service)
	}
	sort.Slice(result.Services, func(i, j int) bool { return result.Services[i].Name < result.Services[j].Name })
	fingerprint, err := destinationFingerprint(result)
	if err != nil {
		return RestorePlan{}, err
	}
	result.DestinationFingerprint = fingerprint
	if err := result.Seal(); err != nil {
		return RestorePlan{}, err
	}
	return result, nil
}

type selectedRestoreService struct {
	snapshot   ServiceManifest
	deployment services.Deployment
}

func restoreServices(manifest Manifest, deployments []services.Deployment, only string) ([]selectedRestoreService, error) {
	byName := map[string]services.Deployment{}
	for _, deployment := range deployments {
		byName[deployment.Name] = deployment
	}
	selected := make([]selectedRestoreService, 0, len(manifest.Services))
	for _, snapshotService := range manifest.Services {
		if only != "" && snapshotService.Name != only {
			continue
		}
		deployment, found := byName[snapshotService.Name]
		if !found || deployment.State == "absent" {
			return nil, errs.New(errs.PlanBlocked, "destination configuration does not declare active service "+snapshotService.Name, nil)
		}
		digest, err := ServiceConfigurationDigest(deployment)
		if err != nil {
			return nil, err
		}
		if digest != snapshotService.ConfigurationDigest {
			return nil, errs.New(errs.PlanBlocked, "destination service configuration does not match snapshot for "+snapshotService.Name, nil)
		}
		selected = append(selected, selectedRestoreService{snapshot: snapshotService, deployment: deployment})
	}
	if only != "" && len(selected) == 0 {
		return nil, errs.New(errs.ConfigInvalid, "snapshot does not contain service "+only, nil)
	}
	if len(selected) == 0 {
		return nil, errs.New(errs.ConfigInvalid, "snapshot contains no restorable declared services", nil)
	}
	return selected, nil
}

type resourceState struct {
	destination   string
	exists, empty bool
}

func destinationState(ctx context.Context, tr transport.Transport, deployment services.Deployment, resource services.PersistentResource) (resourceState, error) {
	switch resource.Type {
	case "volume":
		script := "if " + dockerPrefix() + " volume inspect " + transport.ShellQuote(resource.RuntimeVolume) + " >/dev/null 2>&1; then printf exists=yes\\n; else printf exists=no\\n; fi"
		result, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
		if err != nil {
			return resourceState{}, err
		}
		state := resourceState{destination: resource.RuntimeVolume, exists: strings.Contains(result.Stdout, "exists=yes")}
		if !state.exists {
			return state, nil
		}
		if err := validateDestinationVolume(ctx, tr, deployment, resource); err != nil {
			return resourceState{}, err
		}
		empty, err := emptyVolume(ctx, tr, resource.RuntimeVolume)
		if err != nil {
			return resourceState{}, err
		}
		state.empty = empty
		return state, nil
	case "path":
		script := "if test -e " + transport.ShellQuote(resource.Path) + "; then printf exists=yes\\n; else printf exists=no\\n; fi"
		result, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
		if err != nil {
			return resourceState{}, err
		}
		state := resourceState{destination: resource.Path, exists: strings.Contains(result.Stdout, "exists=yes")}
		if !state.exists {
			return state, nil
		}
		if err := validateDestinationPath(ctx, tr, resource.Path); err != nil {
			return resourceState{}, err
		}
		empty, err := emptyPath(ctx, tr, resource.Path)
		if err != nil {
			return resourceState{}, err
		}
		state.empty = empty
		return state, nil
	default:
		return resourceState{}, fmt.Errorf("unsupported resource type %q", resource.Type)
	}
}

func validateDestinationVolume(ctx context.Context, tr transport.Transport, deployment services.Deployment, resource services.PersistentResource) error {
	if resource.External {
		return nil
	}
	script := "actual=$(" + dockerPrefix() + " volume inspect --format '{{ index .Labels \"com.docker.compose.project\" }}{{ printf \"\\t\" }}{{ index .Labels \"com.docker.compose.volume\" }}' " + transport.ShellQuote(resource.RuntimeVolume) + ")\ntest \"$actual\" = " + transport.ShellQuote(deployment.Project+"\t"+resource.VolumeKey)
	_, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
	return err
}

// Docker's Mountpoint is used only for deterministic emptiness inspection of a
// previously identity-validated volume. Archive capture/extraction still uses
// the unprivileged helper container and never copies Docker's data root.
func emptyVolume(ctx context.Context, tr transport.Transport, volume string) (bool, error) {
	script := "mountpoint=$(" + dockerPrefix() + " volume inspect --format '{{ .Mountpoint }}' " + transport.ShellQuote(volume) + ")\ntest -n \"$mountpoint\"\ntest -d \"$mountpoint\"\nif find \"$mountpoint\" -xdev -mindepth 1 -print -quit | grep -q .; then printf empty=no; else printf empty=yes; fi"
	result, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
	return strings.TrimSpace(result.Stdout) == "empty=yes", err
}

func validateDestinationPath(ctx context.Context, tr transport.Transport, targetPath string) error {
	script := "test -d " + transport.ShellQuote(targetPath) + "\ntest ! -L " + transport.ShellQuote(targetPath) + "\nactual=$(readlink -f -- " + transport.ShellQuote(targetPath) + ")\ntest \"$actual\" = " + transport.ShellQuote(targetPath)
	_, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
	return err
}

func emptyPath(ctx context.Context, tr transport.Transport, targetPath string) (bool, error) {
	result, err := tr.Run(ctx, transport.Request{Script: "if find " + transport.ShellQuote(targetPath) + " -xdev -mindepth 1 -print -quit | grep -q .; then printf empty=no; else printf empty=yes; fi", Privileged: true})
	return strings.TrimSpace(result.Stdout) == "empty=yes", err
}

func destinationFingerprint(plan RestorePlan) (string, error) {
	semantic := struct {
		Target   facts.Identity   `json:"target"`
		Services []RestoreService `json:"services"`
		Policy   string           `json:"policy"`
	}{Target: plan.TargetIdentity, Services: plan.Services, Policy: plan.Policy}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func (plan *RestorePlan) Seal() error {
	if err := validateRestorePlan(*plan); err != nil {
		return err
	}
	fingerprint, err := restorePlanFingerprint(*plan)
	if err != nil {
		return err
	}
	plan.Fingerprint = fingerprint
	return nil
}

func validateRestorePlan(plan RestorePlan) error {
	if plan.SchemaVersion != RestorePlanSchemaVersion || !validSnapshotID(plan.SnapshotID) || len(plan.SnapshotDigest) != 64 || plan.ConfigFingerprint == "" || plan.Target == "" || plan.Policy != "empty-only" || len(plan.Services) == 0 {
		return fmt.Errorf("invalid restore plan")
	}
	if _, err := hex.DecodeString(plan.SnapshotDigest); err != nil {
		return fmt.Errorf("invalid restore snapshot digest")
	}
	previousService := ""
	for _, service := range plan.Services {
		if service.Name == "" || service.Name <= previousService {
			return fmt.Errorf("invalid restore service ordering")
		}
		previousService = service.Name
		previousResource := ""
		for _, resource := range service.Resources {
			if resource.Name == "" || resource.Name <= previousResource || (resource.Type != "volume" && resource.Type != "path") || resource.ArchiveSHA256 == "" || resource.StoredSize < 0 {
				return fmt.Errorf("invalid restore resource")
			}
			if _, err := safeArchivePath(resource.Archive); err != nil {
				return err
			}
			previousResource = resource.Name
		}
	}
	return nil
}

func restorePlanFingerprint(plan RestorePlan) (string, error) {
	plan.Fingerprint = ""
	encoded, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func WriteRestorePlan(filename string, plan RestorePlan) error {
	if err := plan.Seal(); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".bebop-restore-plan-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filename)
}

func LoadRestorePlan(filename string) (RestorePlan, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return RestorePlan{}, err
	}
	var plan RestorePlan
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&plan); err != nil {
		return RestorePlan{}, err
	}
	if err := validateRestorePlan(plan); err != nil {
		return RestorePlan{}, err
	}
	fingerprint, err := restorePlanFingerprint(plan)
	if err != nil || fingerprint != plan.Fingerprint {
		return RestorePlan{}, errs.New(errs.PlanTampered, "restore plan fingerprint does not match", err)
	}
	return plan, nil
}

// ApplyRestore accepts a freshly rebuilt or saved-and-revalidated RestorePlan.
// It repeats snapshot integrity and empty-destination checks after acquiring
// the shared target lock, narrowing review-to-extraction races without claiming
// a distributed transaction.
func ApplyRestore(ctx context.Context, repository Repository, reviewed RestorePlan, request RestoreRequest) (result RestoreResult, resultErr error) {
	if err := validateRestorePlan(reviewed); err != nil {
		return result, err
	}
	if fingerprint, err := restorePlanFingerprint(reviewed); err != nil || fingerprint != reviewed.Fingerprint {
		return result, errs.New(errs.PlanTampered, "restore plan fingerprint does not match", err)
	}
	manifest, err := repository.Verify(reviewed.SnapshotID)
	if err != nil {
		return result, err
	}
	if manifest.Digest != reviewed.SnapshotDigest {
		return result, errs.New(errs.PlanStale, "snapshot changed after restore review", nil)
	}
	if !reviewed.TargetIdentity.Matches(request.Host.Identity()) {
		return result, errs.New(errs.TargetIdentityMismatch, "restore target identity changed after review", nil)
	}
	configuration, err := config.Fingerprint(request.Config)
	if err != nil {
		return result, err
	}
	if configuration != reviewed.ConfigFingerprint {
		return result, errs.New(errs.PlanStale, "destination configuration changed after restore review", nil)
	}
	streamer, supported := request.Transport.(transport.StreamTransport)
	if !supported {
		return result, fmt.Errorf("target transport does not support streaming restore archives")
	}
	locker, supported := request.Transport.(transport.ApplyLocker)
	if !supported {
		return result, errs.New(errs.ApplyLocked, "restore requires the Bebop target apply lock", nil)
	}
	lock, err := locker.AcquireApplyLock(ctx)
	if err != nil {
		return result, classifyLock(err)
	}
	defer lock.Release()
	if err := ensureHelper(ctx, request.Transport); err != nil {
		return result, errs.New(errs.PlanBlocked, "restore helper image is unavailable", err)
	}

	deployments, err := services.ResolveAll(request.Config)
	if err != nil {
		return result, err
	}
	selected, err := restoreServices(manifest, deployments, request.Service)
	if err != nil {
		return result, err
	}
	for _, selectedService := range selected {
		fact := serviceFact(request.Host, selectedService.deployment.Name)
		stopped := false
		if serviceIsRunning(fact) {
			if _, err := request.Transport.Run(ctx, transport.Request{Script: modules.ComposeCommand(request.Config.Storage.DataRoot, selectedService.deployment, "stop"), Privileged: true}); err != nil {
				return result, fmt.Errorf("stop service %s for restore: %w", selectedService.deployment.Name, err)
			}
			stopped = true
		}
		restoreErr := restoreServiceResources(ctx, repository, streamer, request.Transport, selectedService, reviewed)
		if stopped && fact.DeploymentPresent {
			restartErr := restartAndVerify(ctx, request.Transport, request.Config, selectedService.deployment)
			if restoreErr != nil && restartErr != nil {
				return result, fmt.Errorf("restore service %s: %v; recovery restart also failed: %w", selectedService.deployment.Name, restoreErr, restartErr)
			}
			if restartErr != nil {
				return result, fmt.Errorf("restore service %s succeeded but restart failed: %w", selectedService.deployment.Name, restartErr)
			}
		}
		if restoreErr != nil {
			return result, restoreErr
		}
		if !fact.DeploymentPresent && selectedService.deployment.State == "running" {
			result.NeedsConvergence = append(result.NeedsConvergence, selectedService.deployment.Name)
		}
	}
	result.Plan = reviewed
	for _, service := range reviewed.Services {
		for _, resource := range service.Resources {
			result.Restored = append(result.Restored, service.Name+"/"+resource.Name)
		}
	}
	return result, nil
}

func restoreServiceResources(ctx context.Context, repository Repository, streamer transport.StreamTransport, tr transport.Transport, service selectedRestoreService, reviewed RestorePlan) error {
	planService, found := plannedRestoreService(reviewed, service.deployment.Name)
	if !found {
		return errs.New(errs.PlanStale, "restore plan no longer contains service "+service.deployment.Name, nil)
	}
	for _, source := range service.snapshot.Resources {
		resource, found := persistentResource(service.deployment, source.Name)
		if !found || resource.Type != source.Type {
			return errs.New(errs.PlanStale, "destination resource mapping changed for "+source.Name, nil)
		}
		state, err := destinationState(ctx, tr, service.deployment, resource)
		if err != nil {
			return err
		}
		planned, found := plannedRestoreResource(planService, source.Name)
		if !found || planned.Destination != state.destination || planned.Exists != state.exists || planned.Empty != state.empty {
			return errs.New(errs.PlanStale, "destination persistent state changed after restore review for "+service.deployment.Name+"/"+source.Name, nil)
		}
		if state.exists && !state.empty {
			return errs.New(errs.PlanBlocked, "restore blocked: destination "+state.destination+" already contains data", nil)
		}
		if !state.exists {
			if err := createDestination(ctx, tr, service.deployment, resource); err != nil {
				return err
			}
		}
		archive, err := repository.OpenArchive(reviewed.SnapshotID, source)
		if err != nil {
			return err
		}
		_, streamErr := streamer.RunStream(ctx, transport.StreamRequest{Script: restoreArchiveScript(resource), Stdin: archive, Privileged: true}, io.Discard)
		closeErr := archive.Close()
		if streamErr != nil {
			return fmt.Errorf("restore %s: %w", source.Name, streamErr)
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func createDestination(ctx context.Context, tr transport.Transport, deployment services.Deployment, resource services.PersistentResource) error {
	switch resource.Type {
	case "volume":
		command := dockerPrefix() + " volume create"
		if !resource.External {
			command += " --label " + transport.ShellQuote("com.docker.compose.project="+deployment.Project) + " --label " + transport.ShellQuote("com.docker.compose.volume="+resource.VolumeKey)
		}
		command += " " + transport.ShellQuote(resource.RuntimeVolume) + " >/dev/null"
		_, err := tr.Run(ctx, transport.Request{Script: command, Privileged: true})
		return err
	case "path":
		_, err := tr.Run(ctx, transport.Request{Script: "install -d -m 0750 -o root -g root -- " + transport.ShellQuote(resource.Path), Privileged: true})
		return err
	default:
		return fmt.Errorf("unsupported resource type %q", resource.Type)
	}
}

func restoreArchiveScript(resource services.PersistentResource) string {
	mount := resource.RuntimeVolume + ":/data"
	if resource.Type == "path" {
		mount = resource.Path + ":/data"
	}
	return dockerPrefix() + " run --rm -i --network none --read-only -v " + transport.ShellQuote(mount) + " " + transport.ShellQuote(HelperImage) + " tar -C /data -xpf -"
}

func persistentResource(deployment services.Deployment, name string) (services.PersistentResource, bool) {
	for _, resource := range deployment.Data {
		if resource.Name == name {
			return resource, true
		}
	}
	return services.PersistentResource{}, false
}
func plannedRestoreService(plan RestorePlan, name string) (RestoreService, bool) {
	for _, service := range plan.Services {
		if service.Name == name {
			return service, true
		}
	}
	return RestoreService{}, false
}
func plannedRestoreResource(service RestoreService, name string) (RestoreResource, bool) {
	for _, resource := range service.Resources {
		if resource.Name == name {
			return resource, true
		}
	}
	return RestoreResource{}, false
}
