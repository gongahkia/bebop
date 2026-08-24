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
	if !cfg.Features.Docker && len(cfg.Services) == 0 {
		return nil, nil, nil
	}
	changes := []plan.Change{}
	if !host.Docker.Installed {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "docker.io is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "distribution-native docker.io package installed", Preconditions: []plan.Precondition{{ID: "docker.engine-absent", Description: "docker.io is still not installed", Script: "! dpkg-query -W -f='${db:Status-Status}' docker.io 2>/dev/null | grep -qx installed"}}, Action: plan.Action{Kind: "docker.install-engine", Script: "export DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y docker.io"}, Verification: "docker.io package is installed"}
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
	if len(cfg.Services) > 0 && !host.Docker.ComposeAvailable {
		dependencies := []string(nil)
		if !host.Docker.Installed {
			dependencies = append(dependencies, "docker.engine")
		}
		if !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
			dependencies = append(dependencies, "docker.service")
		}
		change := plan.Change{ID: "docker.compose", Module: "docker", Summary: "install Docker Compose v2", Reason: "docker compose is unavailable", Risk: plan.Privileged, RequiresRoot: true, Current: "Compose v2 unavailable", Desired: "Docker Compose v2 available for managed services", Dependencies: dependencies, Action: plan.Action{Kind: "docker.install-compose", Resource: host.Docker.ComposePackageAvailable}, Verification: "docker compose version succeeds"}
		if !reviewedComposePackage(host.Docker.ComposePackageAvailable) {
			change.Blocked = "the target apt repositories do not advertise a reviewed Docker Compose v2 package"
		} else {
			change.Action.Script = "export DEBIAN_FRONTEND=noninteractive\napt-get update\napt-get install -y " + host.Docker.ComposePackageAvailable
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

func reviewedComposePackage(candidate string) bool {
	return candidate == "docker-compose-plugin" || candidate == "docker-compose-v2"
}

func (Docker) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "docker.install-engine", "docker.enable-service", "docker.install-compose")
}
func (Docker) Verify(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	if change.Action.Kind == "docker.install-engine" {
		return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' docker.io | grep -qx installed")
	}
	if change.Action.Kind == "docker.install-compose" {
		return verify(ctx, tr, "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null")
	}
	return verify(ctx, tr, "systemctl is-enabled docker.service >/dev/null\nsystemctl is-active docker.service >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null")
}
