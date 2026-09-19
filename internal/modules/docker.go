package modules

import (
	"context"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Docker struct{}

const dockerCESigningKeyFingerprint = "060A61C51B558A7F742B77AAC52FEB6B621E9F35"

func (Docker) Name() string { return "docker" }

func (Docker) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.Docker && len(cfg.Services) == 0 {
		return nil, nil, nil
	}
	if host.OS.Family == "enterprise-linux" && host.PackageManager == "dnf" {
		return planEnterpriseLinuxDocker(host, cfg)
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

func planEnterpriseLinuxDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if host.Docker.ConflictingPackages {
		return []plan.Change{{ID: "docker.conflict", Module: "docker", Summary: "review conflicting container packages", Reason: "an incompatible distribution Docker/runtime package is installed", Risk: plan.Privileged, RequiresRoot: true, Current: "a conflicting RPM package is installed", Desired: "the reviewed Docker CE stack is the sole Docker runtime package set", Action: plan.Action{Kind: "docker.conflict", Resource: "enterprise-linux"}, Verification: "no conflicting Docker runtime package is installed", Blocked: "Enterprise Linux Docker support will not remove existing distribution Docker/runtime packages automatically; resolve the conflicting package stack manually before apply"}}, nil, nil
	}
	if host.Docker.RepositoryState == "unmanaged" {
		return []plan.Change{{ID: "docker.repository", Module: "docker", Summary: "review Docker repository ownership", Reason: "an unmanaged Docker repository definition exists", Risk: plan.Privileged, RequiresRoot: true, Current: "unmanaged Docker RPM repository", Desired: "Bebop-reviewed Docker CE stable repository", Action: plan.Action{Kind: "docker.repository-conflict", Resource: host.Docker.RepositoryPolicy}, Verification: "not applicable until repository ownership is resolved", Blocked: "Bebop will not trust an unmanaged Docker repository definition; review it manually before Docker CE management"}}, nil, nil
	}
	family, major, ok := facts.DockerCERepositoryPolicy(host.OS)
	if !ok {
		return nil, nil, nil
	}
	policy := family + "-" + major
	changes := []plan.Change{}
	// A complete RPM set without Bebop's reviewed repository is not a trusted
	// converged Docker CE state: the same action establishes the fixed source
	// before reconciling the fixed package set.
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete || host.Docker.RepositoryState != "managed"
	if needEngine {
		reason := "the reviewed Docker CE package stack is incomplete"
		current := "Docker CE engine, CLI, containerd, Buildx, or Compose plugin is not installed"
		if host.Docker.PackageSetComplete && host.Docker.RepositoryState != "managed" {
			reason = "the reviewed Docker CE repository is absent"
			current = "Docker CE packages are present without Bebop's reviewed repository"
		}
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: reason, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "Docker CE, CLI, containerd, Buildx, and Compose plugin installed from the reviewed repository", Preconditions: []plan.Precondition{{ID: "docker.no-runtime-conflict", Description: "incompatible distribution Docker/runtime packages are still absent", Script: enterpriseDockerNoConflictScript}, {ID: "docker.repository-safe", Description: "the Docker CE repository is absent or Bebop-managed", Script: enterpriseDockerRepositorySafeScript(family, major)}}, Action: plan.Action{Kind: "docker.install-engine", Resource: policy, Script: enterpriseDockerInstallScript(family, major)}, Verification: "reviewed Docker CE packages are installed"}
		if host.Docker.RepositoryState == "managed" && !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the reviewed Docker CE repository does not advertise the required package set"
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
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: current, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "docker.service enabled, active, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: policy, Script: "systemctl enable --now docker.service"}, Verification: "docker.service is enabled and docker info succeeds as root"}
		if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Blocked = "Enterprise Linux Docker package installation is blocked"
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
		change := plan.Change{ID: "docker.compose", Module: "docker", Summary: "install Docker Compose v2", Reason: "docker compose is unavailable", Risk: plan.Privileged, RequiresRoot: true, Current: "Compose v2 unavailable", Desired: "Docker Compose v2 available for managed services", Dependencies: dependencies, Action: plan.Action{Kind: "docker.install-compose", Resource: policy, Script: "dnf -y install docker-compose-plugin"}, Verification: "docker compose version succeeds"}
		if host.Docker.RepositoryState == "managed" && host.Docker.ComposePackageAvailable != "docker-compose-plugin" {
			change.Action.Script = ""
			change.Blocked = "the reviewed Docker CE repository does not advertise docker-compose-plugin"
		} else if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script = ""
			change.Blocked = "Enterprise Linux Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

const enterpriseDockerNoConflictScript = `for package in moby-engine moby-cli docker containerd; do
  if rpm -q "$package" >/dev/null 2>&1; then exit 1; fi
done`

func enterpriseDockerRepositorySafeScript(family, major string) string {
	baseURL := "https://download.docker.com/linux/" + family + "/" + major + "/$basearch/stable"
	keyURL := "https://download.docker.com/linux/" + family + "/gpg"
	return `if test -e /etc/yum.repos.d/docker-ce-stable.repo; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/yum.repos.d/docker-ce-stable.repo
  grep -Fqx ` + transport.ShellQuote("baseurl="+baseURL) + ` /etc/yum.repos.d/docker-ce-stable.repo
  grep -Fqx 'gpgcheck=1' /etc/yum.repos.d/docker-ce-stable.repo
  grep -Fqx ` + transport.ShellQuote("gpgkey="+keyURL) + ` /etc/yum.repos.d/docker-ce-stable.repo
fi
for candidate in /etc/yum.repos.d/*.repo; do
  test -f "$candidate" || continue
  test "$candidate" = /etc/yum.repos.d/docker-ce-stable.repo && continue
  ! grep -Fq ` + transport.ShellQuote("download.docker.com/linux/"+family+"/") + ` "$candidate" 2>/dev/null
done`
}

func enterpriseDockerInstallScript(family, major string) string {
	baseURL := "https://download.docker.com/linux/" + family + "/" + major + "/$basearch/stable"
	keyURL := "https://download.docker.com/linux/" + family + "/gpg"
	return `set -eu
command -v curl >/dev/null 2>&1
command -v gpg >/dev/null 2>&1
key_tmp=$(mktemp /tmp/.bebop-docker-ce-key.XXXXXX)
trap 'rm -f "$key_tmp"' EXIT
curl --fail --silent --show-error --location ` + transport.ShellQuote(keyURL) + ` --output "$key_tmp"
fingerprint=$(gpg --show-keys --with-colons "$key_tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
test "$fingerprint" = ` + transport.ShellQuote(dockerCESigningKeyFingerprint) + `
	rpm --import "$key_tmp"
	tmp=$(mktemp /etc/yum.repos.d/.docker-ce-stable.repo.XXXXXX)
	trap 'rm -f "$key_tmp" "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[docker-ce-stable]
name=Docker CE Stable
baseurl=` + baseURL + `
enabled=1
gpgcheck=1
gpgkey=` + keyURL + `
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
	mv -f "$tmp" /etc/yum.repos.d/docker-ce-stable.repo
rm -f "$key_tmp"
trap - EXIT
dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
	rpm -qa --qf '%{VERSION}\n' gpg-pubkey | grep -Fxi ` + transport.ShellQuote(dockerCESigningKeyFingerprint)
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
		if change.Action.Resource == "centos-9" || change.Action.Resource == "centos-10" || change.Action.Resource == "rhel-9" || change.Action.Resource == "rhel-10" {
			return verify(ctx, tr, "rpm -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null\nrpm -qa --qf '%{VERSION}\\n' gpg-pubkey | grep -Fxi "+transport.ShellQuote(dockerCESigningKeyFingerprint))
		}
		return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' docker.io | grep -qx installed")
	}
	if change.Action.Kind == "docker.install-compose" {
		return verify(ctx, tr, "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null")
	}
	return verify(ctx, tr, "systemctl is-enabled docker.service >/dev/null\nsystemctl is-active docker.service >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null")
}
