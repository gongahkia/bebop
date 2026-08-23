package modules

import (
	"context"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Docker struct{}

func (Docker) Name() string { return "docker" }

func (Docker) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.Docker {
		return nil, nil, nil
	}
	changes := []plan.Change{}
	if !host.Docker.Installed {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "docker.io is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "distribution-native docker.io package installed", Action: plan.Action{Kind: "docker.install-engine", Script: "export DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y docker.io"}, Verification: "docker.io package is installed"}
		rootBlocked(&change, host.SudoAvailable)
		changes = append(changes, change)
	}
	if !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
		dependencies := []string(nil)
		if !host.Docker.Installed {
			dependencies = []string{"docker.engine"}
		}
		current := "service disabled or inactive"
		if host.Docker.ServiceEnabled && host.Docker.ServiceActive {
			current = "daemon does not respond to privileged docker info"
		}
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: current, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "docker.service enabled, active, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Script: "systemctl enable --now docker.service"}, Verification: "docker.service is enabled and docker info succeeds as root"}
		rootBlocked(&change, host.SudoAvailable)
		changes = append(changes, change)
	}
	return changes, nil, nil
}

func (Docker) Apply(ctx context.Context, tr transport.Transport, change plan.Change) error {
	return runAction(ctx, tr, change, "docker.install-engine", "docker.enable-service")
}
func (Docker) Verify(ctx context.Context, tr transport.Transport, change plan.Change) error {
	if change.Action.Kind == "docker.install-engine" {
		return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' docker.io | grep -qx installed")
	}
	return verify(ctx, tr, "systemctl is-enabled docker.service >/dev/null\nsystemctl is-active docker.service >/dev/null\ndocker info >/dev/null")
}
