// Package preflight performs the shared, read-only manageability assessment
// used by bootstrap and doctor. It intentionally reuses Service.Inspect so
// bootstrap cannot drift into a second remote probing implementation.
package preflight

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/recipes"
	storagepolicy "github.com/bebop-home/bebop/internal/storage"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

type Status string

const (
	Pass Status = "pass"
	Warn Status = "warn"
	Fail Status = "fail"
)

type Check struct {
	Status  Status `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Result is an inspectable answer to whether Bebop can safely manage a host.
// Facts are present only when remote observation completed successfully.
type Result struct {
	Target         string                `json:"target"`
	Reachable      bool                  `json:"reachable"`
	Authenticated  bool                  `json:"authenticated"`
	CommandReady   bool                  `json:"command_ready"`
	SudoAvailable  bool                  `json:"sudo_available"`
	SupportedOS    bool                  `json:"supported_os"`
	Architecture   bool                  `json:"architecture_supported"`
	PackageManager string                `json:"package_manager,omitempty"`
	InitSystem     facts.InitSystem      `json:"init_system,omitempty"`
	Systemd        bool                  `json:"systemd"`
	Ready          bool                  `json:"ready"`
	Failure        transport.FailureKind `json:"failure,omitempty"`
	Error          string                `json:"error,omitempty"`
	Facts          *facts.HostFacts      `json:"facts,omitempty"`
	Checks         []Check               `json:"checks"`
}

func Run(ctx context.Context, service *bebop.Service, current target.Target, cfg config.Config) Result {
	result := Result{Target: current.String()}
	if current.Kind == target.SSH {
		if _, err := exec.LookPath("ssh"); err != nil {
			return unavailable(result, transport.FailureSSHClient, "the controller does not have an ssh client in PATH")
		}
	}
	host, _, err := service.Inspect(ctx, current, cfg)
	if err != nil {
		return unavailable(result, transport.ClassifyFailure(err), failureMessage(transport.ClassifyFailure(err), err))
	}
	result = FromFacts(current, host)
	appendBackupChecks(&result, cfg)
	appendStorageChecks(&result, cfg, host)
	appendRecipeChecks(&result, cfg, host.Architecture)
	result.Ready = !hasFailure(result.Checks)
	return result
}

func appendStorageChecks(result *Result, cfg config.Config, host facts.HostFacts) {
	for _, assessment := range storagepolicy.AssessAll(cfg.Storage, host.Storage) {
		code := "storage." + assessment.Resource.Name
		if assessment.State == storagepolicy.Ready {
			result.Checks = append(result.Checks, Check{Status: Pass, Code: code, Message: "storage " + assessment.Resource.Name + " ready at " + assessment.Resource.Mount})
			continue
		}
		status := Fail
		if assessment.Resource.ManagedMount && (assessment.State == storagepolicy.Missing || assessment.State == storagepolicy.RootSpill) {
			status = Warn
		}
		result.Checks = append(result.Checks, Check{Status: status, Code: code, Message: "storage " + assessment.Resource.Name + " is " + string(assessment.State) + ": " + assessment.Detail})
	}
}

// FromFacts is deterministic and exists both for focused tests and callers
// that have already completed the single shared inspection step.
func FromFacts(current target.Target, host facts.HostFacts) Result {
	result := Result{Target: current.String()}
	result.Reachable = true
	result.Authenticated = true
	result.CommandReady = true
	result.Facts = &host
	result.Checks = append(result.Checks, Check{Status: Pass, Code: "target.reachable", Message: "target reachable and command execution available"})
	if current.Kind == target.SSH {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "ssh.authenticated", Message: "SSH authentication succeeded using the controller's OpenSSH configuration"})
	}
	result.SupportedOS = host.OS.IsSupported()
	if result.SupportedOS {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "os.supported", Message: "supported OS: " + host.OS.Display()})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "os.unsupported", Message: "unsupported target OS: " + host.OS.Display()})
	}
	result.Architecture = host.ArchitectureKnown && host.OS.SupportsArchitecture(host.Architecture)
	if host.OS.Family == "void" && !facts.VoidLibcSupported(host.OS, host.Libc) {
		result.Architecture = false
	}
	if host.ArchitectureKnown {
		if result.Architecture {
			result.Checks = append(result.Checks, Check{Status: Pass, Code: "architecture.supported", Message: "supported target architecture: " + host.Architecture})
		} else {
			result.Checks = append(result.Checks, Check{Status: Fail, Code: "architecture.unsupported", Message: "unsupported or unknown target architecture: " + host.Architecture})
		}
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "architecture.unsupported", Message: "unsupported or unknown target architecture: " + host.Architecture})
	}
	result.PackageManager = host.PackageManager
	if facts.PackageToolsAvailable(host.OS, host.PackageManager, host.PackageDatabase) {
		manager, database, _ := facts.RequiredPackageTools(host.OS)
		message := manager + " package tool available"
		if database != "" {
			message = manager + " and " + database + " package tools available"
		}
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "package_manager." + manager, Message: message})
	} else {
		manager, database, known := facts.RequiredPackageTools(host.OS)
		if !known {
			manager, database = "reviewed", "package"
		}
		required := manager
		if database != "" {
			required += "/" + database
		}
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "package_manager.unsupported", Message: "required " + required + " package tools are unavailable"})
	}
	result.InitSystem = host.InitSystem
	result.Systemd = host.Systemd
	if facts.InitSystemAvailable(host.OS, host.InitSystem, host.Systemd) {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "init." + string(host.OS.RequiredInitSystem()), Message: string(host.OS.RequiredInitSystem()) + " available"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "init.unsupported", Message: "required " + string(host.OS.RequiredInitSystem()) + " init system unavailable"})
	}
	if host.MutationBlocked {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "target.mutation_unsupported", Message: "target mutation is unsafe: " + host.MutationBlockReason})
	}
	result.SudoAvailable = host.SudoAvailable
	if host.SudoAvailable {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "privilege.noninteractive", Message: "non-interactive root access available"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "privilege.unavailable", Message: "non-interactive root, sudo, or doas access unavailable; Bebop cannot apply privileged changes"})
	}
	if host.OS.Family == "alpine" || host.OS.Family == "void" || host.OS.Family == "devuan" || host.OS.Family == "artix" {
		remediation := "install flock findmnt lsblk manually with apk"
		if host.OS.Family == "void" {
			remediation = "install util-linux manually with xbps-install -S"
		}
		if host.OS.Family == "devuan" {
			remediation = "install flock and util-linux manually with apt-get"
		}
		if host.OS.Family == "artix" {
			remediation = "install util-linux manually with pacman -S"
		}
		for _, tool := range []struct {
			name      string
			available bool
		}{{"flock", host.RequiredTools.Flock}, {"lsblk", host.RequiredTools.LSBLK}, {"findmnt", host.RequiredTools.Findmnt}} {
			name, available := tool.name, tool.available
			if available {
				result.Checks = append(result.Checks, Check{Status: Pass, Code: "target.tool." + name, Message: name + " available"})
			} else {
				result.Checks = append(result.Checks, Check{Status: Fail, Code: "target.tool." + name, Message: host.OS.Display() + " requires " + name + " before mutation; " + remediation})
			}
		}
	}
	appendOperationalChecks(&result, host)
	result.Ready = !hasFailure(result.Checks)
	return result
}

func unavailable(result Result, kind transport.FailureKind, message string) Result {
	result.Failure = kind
	result.Error = message
	result.Checks = []Check{{Status: Fail, Code: "transport." + string(kind), Message: message}}
	return result
}

func appendOperationalChecks(result *Result, host facts.HostFacts) {
	if host.SSH.Installed && !host.SSH.ConfigValid {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "ssh.config_invalid", Message: "current SSH configuration does not validate; SSH hardening will be blocked"})
	} else if host.SSH.Installed {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "ssh.config_valid", Message: "SSH configuration validates"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "ssh.server_absent", Message: "no SSH server found; SSH hardening has no effect"})
	}
	if host.Docker.Responsive {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "docker.healthy", Message: "Docker healthy"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "docker.unhealthy", Message: "Docker is not healthy or not installed"})
	}
	if len(host.Services) > 0 {
		if host.Docker.ComposeAvailable {
			result.Checks = append(result.Checks, Check{Status: Pass, Code: "docker.compose", Message: "Docker Compose v2 available for configured services"})
		} else if host.Docker.ComposePackageAvailable != "" {
			result.Checks = append(result.Checks, Check{Status: Warn, Code: "docker.compose_missing", Message: "Docker Compose v2 missing; Bebop can install " + host.Docker.ComposePackageAvailable + " during a reviewed service plan"})
		} else {
			result.Checks = append(result.Checks, Check{Status: Fail, Code: "docker.compose_missing", Message: "Docker Compose v2 missing and no reviewed package is advertised by the target package manager"})
		}
		for _, service := range host.Services {
			if service.DesiredState == "running" && service.DeploymentPresent && service.Runtime == "running" && (service.Health == "healthy" || service.Health == "no-healthcheck") {
				result.Checks = append(result.Checks, Check{Status: Pass, Code: "service." + service.Name, Message: "service " + service.Name + " running (" + service.Health + ")"})
			} else if service.DesiredState == "absent" && !service.DeploymentPresent && service.Runtime == "missing" {
				result.Checks = append(result.Checks, Check{Status: Pass, Code: "service." + service.Name, Message: "service " + service.Name + " absent"})
			} else {
				result.Checks = append(result.Checks, Check{Status: Warn, Code: "service." + service.Name, Message: "service " + service.Name + " requires convergence (runtime " + service.Runtime + ", health " + service.Health + ")"})
			}
		}
	}
	if host.Tailscale.Connected {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "tailscale.connected", Message: "Tailscale connected"})
	} else if host.Tailscale.Installed {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "tailscale.authentication", Message: "Tailscale installed but not authenticated"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "tailscale.absent", Message: "Tailscale not installed"})
	}
	if host.DataRoot.Exists && host.DataRoot.Mode == "750" && host.DataRoot.UID == 0 && host.DataRoot.GID == 0 {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "data_root.ready", Message: host.DataRoot.Path + " has Bebop data-root ownership and mode"})
	} else if host.DataRoot.Exists {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "data_root.drift", Message: host.DataRoot.Path + " does not match Bebop data-root ownership and mode"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "data_root.absent", Message: host.DataRoot.Path + " does not exist yet"})
	}
	if host.Firewall.UFWActive || host.Firewall.OtherActive {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "firewall.external", Message: "an existing firewall is active; Bebop does not modify it"})
	}
	for _, device := range host.UnconfiguredStorage {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "storage.unconfigured", Message: "unconfigured storage detected: " + device.Name + "; Bebop will not modify disk layouts"})
	}
}

// appendBackupChecks deliberately remains controller-local and read-only. A
// normal doctor must not create a repository, pull a helper image, or scan
// potentially large declared data resources.
func appendBackupChecks(result *Result, cfg config.Config) {
	resources := 0
	for _, service := range cfg.Services {
		resources += len(service.Data)
	}
	if resources == 0 {
		return
	}
	result.Checks = append(result.Checks, Check{Status: Pass, Code: "backup.resources_declared", Message: fmt.Sprintf("%d explicit persistent data resource(s) declared for backup", resources)})
	destination := cfg.Backup.Destination
	if !filepath.IsAbs(destination) {
		if cfg.SourceDirectory() == "" {
			result.Checks = append(result.Checks, Check{Status: Warn, Code: "backup.destination_unresolved", Message: "relative backup destination needs a file-backed configuration"})
			return
		}
		destination = filepath.Join(cfg.SourceDirectory(), destination)
	}
	info, err := os.Lstat(destination)
	if os.IsNotExist(err) {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "backup.destination_absent", Message: "backup destination will be created on first backup: " + destination})
		return
	}
	if err != nil {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "backup.destination_unavailable", Message: "cannot inspect backup destination: " + err.Error()})
		return
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "backup.destination_unsafe", Message: "backup destination must be a real controller directory"})
		return
	}
	result.Checks = append(result.Checks, Check{Status: Pass, Code: "backup.destination_ready", Message: "backup destination is a controller-side directory: " + destination})
}

func appendRecipeChecks(result *Result, cfg config.Config, architecture string) {
	managed, err := recipes.Managed(cfg)
	if err != nil {
		result.Checks = append(result.Checks, Check{Status: Warn, Code: "recipe.metadata_unavailable", Message: "recipe metadata could not be loaded: " + err.Error()})
		return
	}
	for _, service := range managed {
		if service.Recipe.SupportsArchitecture(architecture) {
			result.Checks = append(result.Checks, Check{Status: Pass, Code: "recipe." + service.Service.Name + ".architecture", Message: "recipe " + service.Recipe.ID + "@" + service.Recipe.Version + " supports " + architecture})
		} else {
			result.Checks = append(result.Checks, Check{Status: Fail, Code: "recipe." + service.Service.Name + ".architecture", Message: "recipe " + service.Recipe.ID + " does not support target architecture " + architecture})
		}
	}
}

func hasFailure(checks []Check) bool {
	for _, check := range checks {
		if check.Status == Fail {
			return true
		}
	}
	return false
}

func (result Result) FailureError() error {
	if result.Ready {
		return nil
	}
	if result.Failure != "" {
		return errs.New(codeForFailure(result.Failure), result.Error, nil)
	}
	for _, check := range result.Checks {
		if check.Status != Fail {
			continue
		}
		switch check.Code {
		case "privilege.unavailable":
			return errs.New(errs.PrivilegeUnavailable, check.Message, nil)
		case "os.unsupported", "architecture.unsupported", "package_manager.unsupported", "init.unsupported":
			return errs.New(errs.UnsupportedOS, check.Message, nil)
		}
	}
	return errs.New(errs.TargetUnreachable, "target is not ready", nil)
}

func codeForFailure(kind transport.FailureKind) errs.Code {
	switch kind {
	case transport.FailureAuthentication:
		return errs.TargetAuthentication
	case transport.FailureHostKey:
		return errs.TargetHostKey
	case transport.FailureTimeout:
		return errs.TargetTimeout
	default:
		return errs.TargetUnreachable
	}
}

func failureMessage(kind transport.FailureKind, cause error) string {
	switch kind {
	case transport.FailureDNS:
		return "SSH host name could not be resolved"
	case transport.FailureTimeout:
		return "SSH connection timed out"
	case transport.FailureRefused:
		return "SSH connection was refused"
	case transport.FailureHostKey:
		return "SSH host-key verification failed; review known_hosts and SSH configuration"
	case transport.FailureAuthentication:
		return "SSH authentication failed; review the user's OpenSSH configuration and identities"
	case transport.FailureSSHClient:
		return "the controller could not start the ssh client"
	default:
		return fmt.Sprintf("target command failed: %v", cause)
	}
}
