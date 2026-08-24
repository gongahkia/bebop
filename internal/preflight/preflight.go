// Package preflight performs the shared, read-only manageability assessment
// used by bootstrap and doctor. It intentionally reuses Service.Inspect so
// bootstrap cannot drift into a second remote probing implementation.
package preflight

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
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
	Systemd        bool                  `json:"systemd"`
	Ready          bool                  `json:"ready"`
	Failure        transport.FailureKind `json:"failure,omitempty"`
	Error          string                `json:"error,omitempty"`
	Facts          *facts.HostFacts      `json:"facts,omitempty"`
	Checks         []Check               `json:"checks"`
}

func Run(ctx context.Context, service *bebop.Service, current target.Target, dataRoot string) Result {
	result := Result{Target: current.String()}
	if current.Kind == target.SSH {
		if _, err := exec.LookPath("ssh"); err != nil {
			return unavailable(result, transport.FailureSSHClient, "the controller does not have an ssh client in PATH")
		}
	}
	host, _, err := service.Inspect(ctx, current, dataRoot)
	if err != nil {
		return unavailable(result, transport.ClassifyFailure(err), failureMessage(transport.ClassifyFailure(err), err))
	}
	return FromFacts(current, host)
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
	result.SupportedOS = host.OS.Supported
	if host.OS.Supported {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "os.supported", Message: "supported Debian-family OS: " + host.OS.Display()})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "os.unsupported", Message: "unsupported target OS: " + host.OS.Display()})
	}
	result.Architecture = host.ArchitectureKnown
	if host.ArchitectureKnown {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "architecture.supported", Message: "supported target architecture: " + host.Architecture})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "architecture.unsupported", Message: "unsupported or unknown target architecture: " + host.Architecture})
	}
	result.PackageManager = host.PackageManager
	if host.PackageManager == "apt" {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "package_manager.apt", Message: "apt and dpkg package tools available"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "package_manager.unsupported", Message: "required apt/dpkg package tools are unavailable"})
	}
	result.Systemd = host.Systemd
	if host.Systemd {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "init.systemd", Message: "systemd available"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "init.unsupported", Message: "systemd unavailable; Bebop requires systemd"})
	}
	result.SudoAvailable = host.SudoAvailable
	if host.SudoAvailable {
		result.Checks = append(result.Checks, Check{Status: Pass, Code: "privilege.noninteractive", Message: "non-interactive root access available"})
	} else {
		result.Checks = append(result.Checks, Check{Status: Fail, Code: "privilege.unavailable", Message: "non-interactive sudo/root access unavailable; Bebop cannot apply privileged changes"})
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
