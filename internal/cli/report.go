package cli

import (
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
)

type Check struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}
type DoctorReport struct {
	Target string  `json:"target"`
	Checks []Check `json:"checks"`
}

func doctorReport(host facts.HostFacts) DoctorReport {
	checks := []Check{{"success", "target reachable"}}
	if host.OS.Supported {
		checks = append(checks, Check{"success", "Debian-family OS supported: " + host.OS.Display()})
	} else {
		checks = append(checks, Check{"failure", "unsupported target OS: " + host.OS.Display()})
	}
	if host.Systemd {
		checks = append(checks, Check{"success", "systemd available"})
	} else {
		checks = append(checks, Check{"failure", "systemd unavailable; Bebop M0 requires systemd"})
	}
	if host.SudoAvailable {
		checks = append(checks, Check{"success", "non-interactive privilege escalation available"})
	} else {
		checks = append(checks, Check{"warning", "non-interactive sudo unavailable; privileged changes will be blocked"})
	}
	if host.SSH.Installed && !host.SSH.ConfigValid {
		checks = append(checks, Check{"warning", "current SSH configuration does not validate with sshd -t"})
	} else if host.SSH.Installed {
		checks = append(checks, Check{"success", "SSH configuration validates"})
	}
	if host.Docker.Responsive {
		checks = append(checks, Check{"success", "Docker healthy"})
	} else {
		checks = append(checks, Check{"warning", "Docker is not healthy or not installed"})
	}
	if host.Tailscale.Connected {
		checks = append(checks, Check{"success", "Tailscale connected"})
	} else if host.Tailscale.Installed {
		checks = append(checks, Check{"warning", "Tailscale installed but not authenticated"})
	} else {
		checks = append(checks, Check{"warning", "Tailscale not installed"})
	}
	if host.DataRoot.Exists && host.DataRoot.Mode == "750" && host.DataRoot.UID == 0 && host.DataRoot.GID == 0 {
		checks = append(checks, Check{"success", host.DataRoot.Path + " exists with Bebop data-root ownership and mode"})
	} else if host.DataRoot.Exists {
		checks = append(checks, Check{"warning", host.DataRoot.Path + " exists but does not match Bebop data-root ownership and mode"})
	} else {
		checks = append(checks, Check{"warning", host.DataRoot.Path + " does not exist yet"})
	}
	if host.Firewall.UFWActive || host.Firewall.OtherActive {
		checks = append(checks, Check{"warning", "an existing firewall is active; Bebop M0 will not modify it"})
	}
	for _, device := range host.UnconfiguredStorage {
		checks = append(checks, Check{"warning", "unconfigured storage detected: " + device.Name + "; Bebop M0 will not modify disk layouts"})
	}
	return DoctorReport{Target: host.Target, Checks: checks}
}

type StatusReport struct {
	Host                string                `json:"host"`
	OS                  string                `json:"os"`
	Architecture        string                `json:"architecture"`
	Docker              string                `json:"docker"`
	Tailscale           string                `json:"tailscale"`
	Updates             string                `json:"updates"`
	SSH                 string                `json:"ssh"`
	DataRoot            string                `json:"data_root"`
	UnconfiguredStorage []facts.StorageDevice `json:"unconfigured_storage,omitempty"`
	Overall             string                `json:"overall"`
}

func statusReport(host facts.HostFacts) StatusReport {
	report := StatusReport{Host: host.Hostname, OS: host.OS.Display(), Architecture: host.Architecture, Docker: dockerState(host), Tailscale: tailscaleState(host), Updates: "disabled", SSH: "not hardened", DataRoot: "missing", UnconfiguredStorage: host.UnconfiguredStorage, Overall: "needs attention"}
	if host.AutomaticUpdates.Installed && host.AutomaticUpdates.Enabled {
		report.Updates = "enabled"
	}
	if host.SSH.BebopDropIn == modules.SSHDropIn {
		report.SSH = "hardened"
	}
	if host.DataRoot.Exists {
		report.DataRoot = host.DataRoot.Path
	}
	if host.Docker.Responsive && host.Tailscale.Connected && report.Updates == "enabled" && report.SSH == "hardened" && host.DataRoot.Exists {
		report.Overall = "healthy"
	}
	return report
}

func dockerState(host facts.HostFacts) string {
	if !host.Docker.Installed {
		return "not installed"
	}
	if host.Docker.Responsive {
		return "healthy"
	}
	if host.Docker.ServiceActive {
		return "service active, not responsive"
	}
	return "installed, service inactive"
}
func tailscaleState(host facts.HostFacts) string {
	if !host.Tailscale.Installed {
		return "not installed"
	}
	if host.Tailscale.Connected {
		return "connected"
	}
	return "installed, authentication required"
}
