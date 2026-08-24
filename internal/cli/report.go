package cli

import (
	"fmt"
	"sort"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/preflight"
	storagepolicy "github.com/bebop-home/bebop/internal/storage"
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
	Services            []ServiceStatus       `json:"services,omitempty"`
	UnconfiguredStorage []facts.StorageDevice `json:"unconfigured_storage,omitempty"`
	StorageAvailable    bool                  `json:"storage_available"`
	Storage             []StorageStatus       `json:"storage,omitempty"`
	Overall             string                `json:"overall"`
}

type ServiceStatus struct {
	Name       string `json:"name"`
	Desired    string `json:"desired"`
	Runtime    string `json:"runtime"`
	Health     string `json:"health"`
	Deployment string `json:"deployment"`
}

type StorageStatus struct {
	Name  string `json:"name"`
	Mount string `json:"mount"`
	State string `json:"state"`
}

func statusReport(host facts.HostFacts, cfg config.Config) StatusReport {
	report := StatusReport{Host: host.Hostname, OS: host.OS.Display(), Architecture: host.Architecture, Docker: dockerState(host), Tailscale: tailscaleState(host), Updates: "disabled", SSH: "not hardened", DataRoot: "missing", UnconfiguredStorage: host.UnconfiguredStorage, StorageAvailable: host.Storage.Available, Overall: "needs attention"}
	if host.AutomaticUpdates.Installed && host.AutomaticUpdates.Enabled {
		report.Updates = "enabled"
	}
	if host.SSH.BebopDropIn == modules.SSHDropIn && host.SSH.HardeningEffective {
		report.SSH = "hardened"
	}
	if host.DataRoot.Exists {
		report.DataRoot = host.DataRoot.Path
	}
	storageHealthy := true
	for _, assessment := range storagepolicy.AssessAll(cfg.Storage, host.Storage) {
		report.Storage = append(report.Storage, StorageStatus{Name: assessment.Resource.Name, Mount: assessment.Resource.Mount, State: string(assessment.State)})
		storageHealthy = storageHealthy && assessment.State == storagepolicy.Ready
	}
	servicesHealthy := true
	for _, service := range host.Services {
		deployment := "missing"
		if service.DeploymentUnsafe {
			deployment = "unsafe"
		} else if service.DeploymentPresent {
			deployment = "managed"
		}
		report.Services = append(report.Services, ServiceStatus{Name: service.Name, Desired: service.DesiredState, Runtime: service.Runtime, Health: service.Health, Deployment: deployment})
		switch service.DesiredState {
		case "running":
			servicesHealthy = servicesHealthy && service.DeploymentPresent && service.Runtime == "running" && (service.Health == "healthy" || service.Health == "no-healthcheck")
		case "stopped":
			servicesHealthy = servicesHealthy && service.DeploymentPresent && (service.Runtime == "stopped" || service.Runtime == "missing")
		case "absent":
			servicesHealthy = servicesHealthy && !service.DeploymentPresent && !service.DeploymentUnsafe && service.Runtime == "missing"
		}
	}
	sort.Slice(report.Services, func(i, j int) bool { return report.Services[i].Name < report.Services[j].Name })
	if host.Docker.Responsive && host.Tailscale.Connected && report.Updates == "enabled" && report.SSH == "hardened" && host.DataRoot.Exists && storageHealthy && servicesHealthy {
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

func servicesState(services []ServiceStatus) string {
	if len(services) == 0 {
		return "-"
	}
	ready := 0
	for _, service := range services {
		if service.Desired == "running" && service.Runtime == "running" && (service.Health == "healthy" || service.Health == "no-healthcheck") {
			ready++
		} else if service.Desired == "stopped" && (service.Runtime == "stopped" || service.Runtime == "missing") {
			ready++
		} else if service.Desired == "absent" && service.Runtime == "missing" && service.Deployment == "missing" {
			ready++
		}
	}
	return fmt.Sprintf("%d/%d ready", ready, len(services))
}
