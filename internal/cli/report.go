package cli

import (
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/preflight"
)

type Check = preflight.Check
type DoctorReport struct {
	Target string  `json:"target"`
	Ready  bool    `json:"ready"`
	Checks []Check `json:"checks"`
}

func doctorReport(result preflight.Result) DoctorReport {
	return DoctorReport{Target: result.Target, Ready: result.Ready, Checks: result.Checks}
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
	if host.SSH.BebopDropIn == modules.SSHDropIn && host.SSH.HardeningEffective {
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
