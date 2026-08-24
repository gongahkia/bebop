package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/services"
	storagepolicy "github.com/bebop-home/bebop/internal/storage"
	"github.com/bebop-home/bebop/internal/transport"
)

// Compose is Bebop's built-in generic workload provider. It owns only source
// copied under storage.data_root/services; Compose volumes and bind-mounted
// application data remain outside its deletion boundary.
type Compose struct {
	PollInterval time.Duration
}

func (Compose) Name() string { return "services" }

func (Compose) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	deployments, err := services.ResolveAll(cfg)
	if err != nil {
		return nil, nil, err
	}
	changes := make([]plan.Change, 0)
	for _, deployment := range deployments {
		current := serviceFact(host, deployment.Name)
		dependencies := serviceDependencies(host, deployment.State)
		blocked := serviceBlocked(host, current, deployment.State)
		storageDependencies, storagePreconditions, storageBlocked := serviceStoragePolicy(host, cfg, deployment)
		dependencies = append(dependencies, storageDependencies...)
		if blocked == "" {
			blocked = storageBlocked
		}
		requirements := []string{"docker.engine", "docker.compose"}
		if deployment.State == "absent" {
			if current.DeploymentPresent || current.DeploymentUnsafe || current.Runtime != "missing" {
				change := serviceChange(deployment, "remove", "remove Compose project", "managed deployment or Compose containers remain", serviceCurrent(current), "containers/project removed; persistent volumes and external data preserved", plan.Privileged, dependencies, requirements)
				change.Action = plan.Action{Kind: "service.remove", Resource: deployment.Name}
				change.Blocked = blocked
				if current.DeploymentUnsafe {
					change.Blocked = "the managed deployment path is not a Bebop current-release symlink; resolve it manually before removal"
				}
				rootBlocked(&change, host.SudoAvailable)
				changes = append(changes, change)
			}
			continue
		}

		placementChanged := current.DeploymentPresent && hasStoragePlacement(deployment) && current.PlacementFingerprint != deployment.PlacementFingerprint
		deploymentChanged := !current.DeploymentPresent || current.DeploymentUnsafe || current.DeploymentDigest != deployment.SourceDigest || (deployment.SecretConfigured && current.SecretFingerprint != deployment.SecretFingerprint) || placementChanged
		deployID := ""
		if deploymentChanged {
			kind, summary, reason := "deploy", "deploy Compose source", "managed deployment is missing"
			if current.DeploymentUnsafe {
				reason = "managed deployment path is not a Bebop current-release symlink"
			} else if current.DeploymentPresent && current.DeploymentDigest != deployment.SourceDigest {
				kind, summary, reason = "update", "update Compose source", "deployment content differs from declared source"
			} else if deployment.SecretConfigured && current.SecretFingerprint != deployment.SecretFingerprint {
				kind, summary, reason = "update", "reconcile rotated service secret", "secret input changed without exposing its value"
			} else if placementChanged {
				kind, summary, reason = "placement", "migrate persistent data placement", "persistent data placement differs from the active release"
			}
			risk := plan.Privileged
			if len(deployment.Ports) > 0 {
				risk = plan.NetworkSensitive
			}
			change := serviceChange(deployment, kind, summary, reason, serviceCurrent(current), "source sha256:"+deployment.SourceDigest, risk, dependencies, requirements)
			change.Action = plan.Action{Kind: "service.deploy", Resource: deployment.Name, SourceDigest: deployment.SourceDigest, InputFingerprint: deployment.InputFingerprint, SecretFingerprint: deployment.SecretFingerprint}
			change.Preconditions = append(deploymentPreconditions(cfg.Storage.DataRoot, deployment, current), storagePreconditions...)
			change.Blocked = blocked
			if placementChanged {
				change.Blocked = "persistent data placement changed; use Bebop backup/restore to migrate state before changing service placement"
			}
			if current.DeploymentUnsafe {
				change.Blocked = "the managed deployment path is not a Bebop current-release symlink; Bebop will not replace an unknown path"
			}
			rootBlocked(&change, host.SudoAvailable)
			changes = append(changes, change)
			deployID = change.ID
		}

		switch deployment.State {
		case "running":
			if deployID != "" || current.Runtime != "running" {
				risk := plan.Privileged
				if len(deployment.Ports) > 0 {
					risk = plan.NetworkSensitive
				}
				change := serviceChange(deployment, "start", "start and reconcile Compose project", "desired state is running", current.Runtime, "running (healthy when a healthcheck exists)", risk, appendDependency(dependencies, deployID), requirements)
				change.Action = plan.Action{Kind: "service.start", Resource: deployment.Name, SourceDigest: deployment.SourceDigest, InputFingerprint: deployment.InputFingerprint, SecretFingerprint: deployment.SecretFingerprint}
				change.Preconditions = append([]plan.Precondition(nil), storagePreconditions...)
				change.Blocked = blocked
				rootBlocked(&change, host.SudoAvailable)
				changes = append(changes, change)
			}
		case "stopped":
			if current.Runtime != "stopped" && current.Runtime != "missing" {
				change := serviceChange(deployment, "stop", "stop Compose project", "desired state is stopped", current.Runtime, "containers stopped; deployment and persistent data preserved", plan.Privileged, appendDependency(dependencies, deployID), requirements)
				change.Action = plan.Action{Kind: "service.stop", Resource: deployment.Name, SourceDigest: deployment.SourceDigest, InputFingerprint: deployment.InputFingerprint, SecretFingerprint: deployment.SecretFingerprint}
				change.Blocked = blocked
				rootBlocked(&change, host.SudoAvailable)
				changes = append(changes, change)
			}
		}
	}
	return changes, nil, nil
}

// serviceStoragePolicy makes a declared storage-relative path an operational
// dependency, not just a controller-side string. Missing managed mounts can be
// prepared in the same ordered plan; all other ambiguous topology blocks
// deployment/start before Docker can create a bind path on the root filesystem.
func serviceStoragePolicy(host facts.HostFacts, cfg config.Config, deployment services.Deployment) ([]string, []plan.Precondition, string) {
	dependencies := []string{}
	preconditions := []plan.Precondition{}
	if deployment.State == "absent" {
		return dependencies, preconditions, ""
	}
	seen := map[string]bool{}
	for _, data := range deployment.Data {
		if data.Type != "path" || data.Storage == "" || seen[data.Storage] {
			continue
		}
		seen[data.Storage] = true
		resource, found := storagepolicy.Find(cfg.Storage, data.Storage)
		if !found {
			return dependencies, preconditions, "declared storage " + data.Storage + " is unavailable in the current configuration"
		}
		assessment := storagepolicy.Assess(resource, host.Storage)
		switch assessment.State {
		case storagepolicy.Ready:
			preconditions = append(preconditions, plan.Precondition{ID: "service." + deployment.Name + ".storage." + resource.Name, Description: "declared storage remains mounted with the expected filesystem identity", Script: storagepolicy.ReadyPrecondition(resource)})
		case storagepolicy.Missing, storagepolicy.RootSpill:
			if resource.ManagedMount {
				dependencies = append(dependencies, "storage."+resource.Name+".mount")
				preconditions = append(preconditions, plan.Precondition{ID: "service." + deployment.Name + ".storage." + resource.Name, Description: "declared storage was mounted by the reviewed storage actions", Script: storagepolicy.ReadyPrecondition(resource)})
			} else {
				return dependencies, preconditions, "storage " + resource.Name + " is " + string(assessment.State) + "; mount the declared filesystem manually or enable managed_mount after review"
			}
		default:
			return dependencies, preconditions, "storage " + resource.Name + " is " + string(assessment.State) + "; Bebop will not deploy persistent data there"
		}
	}
	return dependencies, preconditions, ""
}

func hasStoragePlacement(deployment services.Deployment) bool {
	for _, resource := range deployment.Data {
		if resource.Type == "path" && resource.Storage != "" {
			return true
		}
	}
	return false
}

func serviceChange(deployment services.Deployment, suffix, summary, reason, current, desired string, risk plan.Risk, dependencies, requirements []string) plan.Change {
	return plan.Change{
		ID: "service." + deployment.Name + "." + suffix, Module: "services", Summary: summary, Reason: reason,
		Risk: risk, RequiresRoot: true, Current: current, Desired: desired, Dependencies: dependencies,
		Requirements: requirements, Verification: serviceVerification(suffix),
	}
}

func serviceVerification(action string) string {
	switch action {
	case "deploy", "update":
		return "Bebop-owned deployment source is active with the expected content digest"
	case "start":
		return "all project containers are running; healthchecks become healthy before the configured timeout"
	case "stop":
		return "project containers are stopped while deployment and persistent data remain"
	default:
		return "project containers and active deployment are absent; volumes are preserved"
	}
}

func serviceFact(host facts.HostFacts, name string) facts.Service {
	for _, service := range host.Services {
		if service.Name == name {
			return service
		}
	}
	return facts.Service{Name: name, Runtime: "missing", Health: "missing"}
}

func serviceCurrent(service facts.Service) string {
	if service.DeploymentUnsafe {
		return "unsafe managed deployment path"
	}
	if !service.DeploymentPresent {
		return service.Runtime
	}
	if service.DeploymentDigest == "" {
		return "deployment present with unreadable digest"
	}
	return "source sha256:" + service.DeploymentDigest + "; runtime " + service.Runtime
}

func serviceDependencies(host facts.HostFacts, state string) []string {
	dependencies := make([]string, 0, 3)
	if !host.DataRoot.Exists {
		dependencies = append(dependencies, "base.data-root")
	} else if host.DataRoot.Mode != "750" || host.DataRoot.UID != 0 || host.DataRoot.GID != 0 {
		dependencies = append(dependencies, "base.data-root.permissions")
	}
	if !host.Docker.Installed || !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
		dependencies = append(dependencies, "docker.service")
	}
	if !host.Docker.ComposeAvailable {
		dependencies = append(dependencies, "docker.compose")
	}
	if state == "absent" && len(dependencies) == 0 {
		return nil
	}
	return dependencies
}

func serviceBlocked(host facts.HostFacts, service facts.Service, state string) string {
	if !host.Docker.ComposeAvailable && host.Docker.ComposePackageAvailable == "" {
		return "Docker Compose v2 is unavailable and the target does not advertise a reviewed installable Compose package"
	}
	if state != "absent" && service.DeploymentUnsafe {
		return "the managed deployment path is unsafe"
	}
	return ""
}

func appendDependency(dependencies []string, value string) []string {
	result := append([]string(nil), dependencies...)
	if value != "" {
		result = append(result, value)
	}
	return result
}

func deploymentPreconditions(dataRoot string, deployment services.Deployment, current facts.Service) []plan.Precondition {
	currentPath := path.Join(dataRoot, "services", deployment.Name, "current")
	if !current.DeploymentPresent {
		return []plan.Precondition{{ID: "service." + deployment.Name + ".deployment-absent", Description: "the active deployment path is still absent", Script: "test ! -e " + transport.ShellQuote(currentPath)}}
	}
	return []plan.Precondition{{ID: "service." + deployment.Name + ".deployment-stable", Description: "the active deployment digest has not changed", Script: deploymentDigestCheck(dataRoot, deployment.Name, current.DeploymentDigest)}}
}

func (Compose) Apply(ctx context.Context, tr transport.Transport, cfg config.Config, change plan.Change) error {
	if change.Module != "services" {
		return fmt.Errorf("services module refuses change from %q", change.Module)
	}
	deployment, err := services.ResolveOne(cfg, change.Action.Resource)
	if err != nil {
		return err
	}
	if change.Action.Kind != "service.remove" && change.Action.InputFingerprint != deployment.InputFingerprint {
		return fmt.Errorf("service source or secret input changed after review; generate a new plan")
	}
	if err := runServicePreconditions(ctx, tr, change); err != nil {
		return err
	}
	switch change.Action.Kind {
	case "service.deploy":
		if change.Action.SourceDigest != deployment.SourceDigest || change.Action.SecretFingerprint != deployment.SecretFingerprint {
			return fmt.Errorf("service deployment input does not match reviewed action")
		}
		_, err := tr.Run(ctx, transport.Request{Script: prepareStoragePathsScript(cfg, deployment) + "\n" + deployScript(cfg.Storage.DataRoot, deployment), Stdin: deployment.Payload, Privileged: true})
		return err
	case "service.start":
		_, err := tr.Run(ctx, transport.Request{Script: ComposeCommand(cfg.Storage.DataRoot, deployment, "up -d --remove-orphans"), Privileged: true})
		return err
	case "service.stop":
		_, err := tr.Run(ctx, transport.Request{Script: ComposeCommand(cfg.Storage.DataRoot, deployment, "stop"), Privileged: true})
		return err
	case "service.remove":
		_, err := tr.Run(ctx, transport.Request{Script: removeScript(cfg.Storage.DataRoot, deployment), Privileged: true})
		return err
	default:
		return fmt.Errorf("services module refuses unexpected action %q", change.Action.Kind)
	}
}

func prepareStoragePathsScript(cfg config.Config, deployment services.Deployment) string {
	var script strings.Builder
	script.WriteString("set -e\n")
	for _, resource := range deployment.Data {
		if resource.Type != "path" || resource.Storage == "" {
			continue
		}
		storageResource, found := storagepolicy.Find(cfg.Storage, resource.Storage)
		if !found {
			continue
		}
		// Preconditions have already checked mount identity. Every existing
		// component below the declared mount must be a real directory: checking
		// only the final path would allow an ancestor symlink to redirect a
		// newly-created service directory outside its authorized filesystem.
		fmt.Fprintf(&script, "%s\n%s\n", storagepolicy.ReadyPrecondition(storageResource), storagePathSafetyScript(storageResource.Mount, resource.Path))
	}
	return script.String()
}

func storagePathSafetyScript(mount, targetPath string) string {
	return strings.Join([]string{
		"set -e",
		"root=" + transport.ShellQuote(mount),
		"target=" + transport.ShellQuote(targetPath),
		"test -d \"$root\"",
		"test ! -L \"$root\"",
		"case \"$target\" in \"$root\"/*) ;; *) exit 1 ;; esac",
		"relative=${target#\"$root\"/}",
		"current=$root",
		"while test -n \"$relative\"; do",
		"  segment=${relative%%/*}",
		"  test -n \"$segment\"",
		"  current=\"$current/$segment\"",
		"  if test -e \"$current\" || test -L \"$current\"; then test -d \"$current\"; test ! -L \"$current\"; fi",
		"  if test \"$segment\" = \"$relative\"; then relative=; else relative=${relative#*/}; fi",
		"done",
		"install -d -m 0750 -o root -g root -- \"$target\"",
	}, "\n")
}

func (provider Compose) Verify(ctx context.Context, tr transport.Transport, cfg config.Config, change plan.Change) error {
	deployment, err := services.ResolveOne(cfg, change.Action.Resource)
	if err != nil {
		return err
	}
	switch change.Action.Kind {
	case "service.deploy":
		_, err := tr.Run(ctx, transport.Request{Script: deploymentDigestCheck(cfg.Storage.DataRoot, deployment.Name, deployment.SourceDigest) + secretFingerprintCheck(cfg.Storage.DataRoot, deployment) + placementFingerprintCheck(cfg.Storage.DataRoot, deployment), Privileged: true})
		return err
	case "service.start":
		return provider.waitForRunning(ctx, tr, cfg, deployment)
	case "service.stop":
		_, err := tr.Run(ctx, transport.Request{Script: noRunningContainersScript(deployment.Project), Privileged: true})
		return err
	case "service.remove":
		_, err := tr.Run(ctx, transport.Request{Script: removeVerifyScript(cfg.Storage.DataRoot, deployment), Privileged: true})
		return err
	default:
		return fmt.Errorf("services module refuses verification for %q", change.Action.Kind)
	}
}

func runServicePreconditions(ctx context.Context, tr transport.Transport, change plan.Change) error {
	for _, precondition := range change.Preconditions {
		if precondition.ID == "" || precondition.Script == "" {
			return fmt.Errorf("services module refuses invalid precondition for %q", change.ID)
		}
		if _, err := tr.Run(ctx, transport.Request{Script: precondition.Script, Privileged: true}); err != nil {
			return fmt.Errorf("precondition %s (%s) failed: %w", precondition.ID, precondition.Description, err)
		}
	}
	return nil
}

func deployScript(dataRoot string, deployment services.Deployment) string {
	root := path.Join(dataRoot, "services", deployment.Name)
	releases := path.Join(root, "releases")
	release := path.Join(releases, deployment.SourceDigest)
	var script strings.Builder
	fmt.Fprintf(&script, "root=%s\nreleases=%s\nrelease=%s\n", transport.ShellQuote(root), transport.ShellQuote(releases), transport.ShellQuote(release))
	script.WriteString("install -d -m 0750 -o root -g root -- \"$root\" \"$releases\"\nstage=$(mktemp -d \"$root/.stage.XXXXXX\")\ntrap 'rm -rf -- \"$stage\"' EXIT\ntar -x -f - -C \"$stage\"\n")
	for _, file := range deployment.Files {
		fmt.Fprintf(&script, "test -f \"$stage\"/%s\ntest \"$(stat -c '%%a' -- \"$stage\"/%s)\" = %s\ntest \"$(sha256sum -- \"$stage\"/%s | awk '{print $1}')\" = %s\n", transport.ShellQuote(file.Path), transport.ShellQuote(file.Path), transport.ShellQuote(file.Mode), transport.ShellQuote(file.Path), transport.ShellQuote(file.Digest))
	}
	if deployment.SecretConfigured {
		fmt.Fprintf(&script, "test -f \"$stage\"/%s\ntest \"$(stat -c '%%a' -- \"$stage\"/%s)\" = 600\ntest \"$(tr -d '\\n' < \"$stage\"/%s)\" = %s\n", transport.ShellQuote(services.SecretEnvName), transport.ShellQuote(services.SecretEnvName), transport.ShellQuote(services.SecretFingerprintName), transport.ShellQuote(deployment.SecretFingerprint))
	}
	fmt.Fprintf(&script, "test -f \"$stage\"/%s\ntest \"$(tr -d '\\n' < \"$stage\"/%s)\" = %s\n", transport.ShellQuote(services.PlacementFingerprintName), transport.ShellQuote(services.PlacementFingerprintName), transport.ShellQuote(deployment.PlacementFingerprint))
	fmt.Fprintf(&script, "env -i %sPATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose --project-name %s --project-directory \"$stage\" -f \"$stage\"/%s config -q\n", composeEnvironment(deployment), transport.ShellQuote(deployment.Project), transport.ShellQuote(deployment.ComposeFile))
	script.WriteString("if test -e \"$release\"; then rm -rf -- \"$release\"; fi\nmv -- \"$stage\" \"$release\"\nlink=$(mktemp \"$root/.current.XXXXXX\")\nrm -f -- \"$link\"\nln -s -- \"releases/")
	script.WriteString(deployment.SourceDigest)
	script.WriteString("\" \"$link\"\nmv -Tf -- \"$link\" \"$root/current\"\ntrap - EXIT\n")
	return script.String()
}

// ComposeCommand renders a structured operation against an already-validated,
// Bebop-managed service deployment. Backup/restore use it to preserve the
// same project identity and controller-environment boundary as normal apply.
func ComposeCommand(dataRoot string, deployment services.Deployment, command string) string {
	current := path.Join(dataRoot, "services", deployment.Name, "current")
	return "current=" + transport.ShellQuote(current) + "\ntest -L \"$current\"\nenv -i " + composeEnvironment(deployment) + "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose --project-name " + transport.ShellQuote(deployment.Project) + " --project-directory \"$current\" -f \"$current\"/" + transport.ShellQuote(deployment.ComposeFile) + " " + command
}

func composeEnvironment(deployment services.Deployment) string {
	var result strings.Builder
	for _, value := range deployment.StorageEnvironment {
		result.WriteString(transport.ShellQuote(value.Name + "=" + value.Value))
		result.WriteByte(' ')
	}
	return result.String()
}

func removeScript(dataRoot string, deployment services.Deployment) string {
	current := path.Join(dataRoot, "services", deployment.Name, "current")
	return `current=` + transport.ShellQuote(current) + `
if test -L "$current"; then
  compose_file=''
  for candidate in compose.yaml compose.yml docker-compose.yaml docker-compose.yml; do
    if test -f "$current"/"$candidate"; then compose_file=$candidate; break; fi
  done
  if test -n "$compose_file"; then
    env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose --project-name ` + transport.ShellQuote(deployment.Project) + ` --project-directory "$current" -f "$current"/"$compose_file" down --remove-orphans
  else
    ids=$(env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default ps --all --quiet --filter label=com.docker.compose.project=` + transport.ShellQuote(deployment.Project) + `)
    if test -n "$ids"; then env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default rm -f -- $ids; fi
  fi
  rm -f -- "$current"
else
  ids=$(env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default ps --all --quiet --filter label=com.docker.compose.project=` + transport.ShellQuote(deployment.Project) + `)
  if test -n "$ids"; then env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default rm -f -- $ids; fi
fi`
}

func deploymentDigestCheck(dataRoot, name, digest string) string {
	root := path.Join(dataRoot, "services", name)
	current := path.Join(root, "current")
	return `root=` + transport.ShellQuote(root) + `
current=` + transport.ShellQuote(current) + `
test -L "$current"
resolved=$(readlink -f -- "$current")
case "$resolved" in "$root"/releases/*) ;; *) exit 1;; esac
actual=$(cd -- "$current" && find . -type f ! -path './` + services.SecretEnvName + `' ! -path './` + services.SecretFingerprintName + `' ! -path './` + services.PlacementFingerprintName + `' -printf '%P\n' | LC_ALL=C sort | while IFS= read -r file; do
  test -n "$file" || continue
  mode=$(stat -c '%a' -- "$file")
  checksum=$(sha256sum -- "$file" | awk '{print $1}')
  printf '%s\t%s\t%s\n' "$mode" "$checksum" "$file"
done | sha256sum | awk '{print $1}')
test "$actual" = ` + transport.ShellQuote(digest)
}

func secretFingerprintCheck(dataRoot string, deployment services.Deployment) string {
	if !deployment.SecretConfigured {
		return ""
	}
	current := path.Join(dataRoot, "services", deployment.Name, "current", services.SecretFingerprintName)
	return "\ntest \"$(tr -d '\\n' < " + transport.ShellQuote(current) + ")\" = " + transport.ShellQuote(deployment.SecretFingerprint)
}

func placementFingerprintCheck(dataRoot string, deployment services.Deployment) string {
	current := path.Join(dataRoot, "services", deployment.Name, "current", services.PlacementFingerprintName)
	return "\ntest \"$(tr -d '\\n' < " + transport.ShellQuote(current) + ")\" = " + transport.ShellQuote(deployment.PlacementFingerprint)
}

func noRunningContainersScript(project string) string {
	return "! env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default ps --quiet --filter label=com.docker.compose.project=" + transport.ShellQuote(project) + " --filter status=running | grep -q ."
}

func removeVerifyScript(dataRoot string, deployment services.Deployment) string {
	current := path.Join(dataRoot, "services", deployment.Name, "current")
	return "test ! -e " + transport.ShellQuote(current) + "\n! env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default ps --all --quiet --filter label=com.docker.compose.project=" + transport.ShellQuote(deployment.Project) + " | grep -q ."
}

func (provider Compose) waitForRunning(ctx context.Context, tr transport.Transport, cfg config.Config, deployment services.Deployment) error {
	timeout, err := time.ParseDuration(serviceHealthTimeout(cfg, deployment.Name))
	if err != nil {
		return err
	}
	interval := provider.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		runtime, health, count, inspectErr := composeRuntime(ctx, tr, deployment.Project)
		if inspectErr != nil {
			return inspectErr
		}
		if runtime == "running" && (health == "healthy" || health == "no-healthcheck") {
			return nil
		}
		if runtime == "unhealthy" {
			return fmt.Errorf("service %s is unhealthy after Compose reconciliation", deployment.Name)
		}
		if count == 0 && runtime == "missing" {
			return fmt.Errorf("service %s has no containers after Compose reconciliation", deployment.Name)
		}
		ticker := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			ticker.Stop()
			return ctx.Err()
		case <-deadline.C:
			ticker.Stop()
			return fmt.Errorf("service %s did not become ready within %s (runtime %s, health %s)", deployment.Name, timeout, runtime, health)
		case <-ticker.C:
		}
	}
}

// serviceHealthTimeout locates a declared service without retaining mutable
// module state. The resolver already validated the duration in config; this
// fallback only protects custom embeddings from unbounded waits.
func serviceHealthTimeout(cfg config.Config, name string) string {
	for _, service := range cfg.Services {
		if service.Name == name {
			return service.HealthTimeout
		}
	}
	return config.DefaultServiceHealthTimeout
}

type composeContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Restarting bool   `json:"Restarting"`
	Dead       bool   `json:"Dead"`
	Health     *struct {
		Status string `json:"Status"`
	} `json:"Health"`
}

func composeRuntime(ctx context.Context, tr transport.Transport, project string) (string, string, int, error) {
	result, err := tr.Run(ctx, transport.Request{Script: "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default ps --all --quiet --filter label=com.docker.compose.project=" + transport.ShellQuote(project), Privileged: true})
	if err != nil {
		return "unknown", "unknown", 0, err
	}
	ids := strings.Fields(result.Stdout)
	if len(ids) == 0 {
		return "missing", "missing", 0, nil
	}
	states := make([]composeContainerState, 0, len(ids))
	for _, id := range ids {
		result, err := tr.Run(ctx, transport.Request{Script: "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default inspect --format '{{json .State}}' -- " + transport.ShellQuote(id), Privileged: true})
		if err != nil {
			return "unknown", "unknown", len(ids), err
		}
		var state composeContainerState
		if err := json.Unmarshal([]byte(strings.TrimSpace(result.Stdout)), &state); err != nil {
			return "unknown", "unknown", len(ids), err
		}
		states = append(states, state)
	}
	runtime, health, count := aggregateComposeRuntime(states)
	return runtime, health, count, nil
}

func aggregateComposeRuntime(states []composeContainerState) (string, string, int) {
	if len(states) == 0 {
		return "missing", "missing", 0
	}
	allStopped, allRunning, anyStarting, anyUnhealthy, anyHealthcheck, allHealthy := true, true, false, false, false, true
	for _, state := range states {
		if state.Running {
			allStopped = false
		} else {
			allRunning = false
		}
		if state.Restarting || state.Status == "created" {
			anyStarting = true
		}
		if state.Dead || (state.Health != nil && state.Health.Status == "unhealthy") {
			anyUnhealthy = true
		}
		if state.Health != nil {
			anyHealthcheck = true
			if state.Health.Status == "starting" {
				anyStarting = true
			}
			if state.Health.Status != "healthy" {
				allHealthy = false
			}
		}
	}
	if anyUnhealthy {
		return "unhealthy", "unhealthy", len(states)
	}
	if anyStarting {
		return "starting", "starting", len(states)
	}
	if allStopped {
		return "stopped", "stopped", len(states)
	}
	if !allRunning {
		return "unknown", "unknown", len(states)
	}
	if !anyHealthcheck {
		return "running", "no-healthcheck", len(states)
	}
	if allHealthy {
		return "running", "healthy", len(states)
	}
	return "starting", "starting", len(states)
}
