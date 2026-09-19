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
	if host.PackageManager == "dnf5" {
		return planFedoraDocker(host, cfg)
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

func planFedoraDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if host.Docker.ConflictingPackages {
		return []plan.Change{{ID: "docker.conflict", Module: "docker", Summary: "review conflicting Docker packages", Reason: "a Docker CE package is installed", Risk: plan.Privileged, RequiresRoot: true, Current: "Docker CE or its external containerd package is installed", Desired: "only the reviewed Fedora Moby package stack manages Docker", Action: plan.Action{Kind: "docker.conflict", Resource: "fedora"}, Verification: "no conflicting Docker CE package is installed", Blocked: "Fedora Docker support will not mix the reviewed Moby packages with an existing Docker CE installation; remove or migrate the conflicting stack manually before apply"}}, nil, nil
	}
	changes := []plan.Change{}
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed Fedora Moby package stack is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "Moby engine, Docker CLI, or Compose package is not installed", Desired: "moby-engine, docker-cli, and docker-compose installed", Preconditions: []plan.Precondition{{ID: "docker.no-ce-conflict", Description: "Docker CE packages are still absent", Script: fedoraDockerNoConflictScript}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "fedora", Script: "dnf5 -y install moby-engine docker-cli docker-compose"}, Verification: "reviewed Fedora Docker packages are installed"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the target DNF repositories do not advertise the reviewed Fedora Moby package set"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
		dependencies := []string(nil)
		if needEngine {
			dependencies = []string{"docker.engine"}
		}
		current := "service disabled or inactive"
		if host.Docker.ServiceEnabled && host.Docker.ServiceActive {
			current = "daemon does not respond to privileged docker info"
		}
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: current, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "docker.service enabled, active, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "fedora", Script: "systemctl enable --now docker.service"}, Verification: "docker.service is enabled and docker info succeeds as root"}
		if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Blocked = "Fedora Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if len(cfg.Services) > 0 && !host.Docker.ComposeAvailable {
		dependencies := []string(nil)
		if needEngine {
			dependencies = append(dependencies, "docker.engine")
		}
		if !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
			dependencies = append(dependencies, "docker.service")
		}
		change := plan.Change{ID: "docker.compose", Module: "docker", Summary: "install Docker Compose v2", Reason: "docker compose is unavailable", Risk: plan.Privileged, RequiresRoot: true, Current: "Compose v2 unavailable", Desired: "Docker Compose v2 available for managed services", Dependencies: dependencies, Action: plan.Action{Kind: "docker.install-compose", Resource: "docker-compose", Script: "dnf5 -y install docker-compose"}, Verification: "docker compose version succeeds"}
		if host.Docker.ComposePackageAvailable != "docker-compose" {
			change.Action.Script = ""
			change.Blocked = "the target DNF repositories do not advertise the reviewed Fedora docker-compose package"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

const fedoraDockerNoConflictScript = `for package in docker-ce docker-ce-cli containerd.io; do
  if rpm -q "$package" >/dev/null 2>&1; then exit 1; fi
done`

func reviewedComposePackage(candidate string) bool {
	return candidate == "docker-compose-plugin" || candidate == "docker-compose-v2"
}

func (Docker) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "docker.install-engine", "docker.enable-service", "docker.install-compose")
}
func (Docker) Verify(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	if change.Action.Kind == "docker.install-engine" {
		if change.Action.Resource == "fedora" {
			return verify(ctx, tr, "rpm -q moby-engine docker-cli docker-compose >/dev/null")
		}
		return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' docker.io | grep -qx installed")
	}
	if change.Action.Kind == "docker.install-compose" {
		return verify(ctx, tr, "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null")
	}
	return verify(ctx, tr, "systemctl is-enabled docker.service >/dev/null\nsystemctl is-active docker.service >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null")
}
