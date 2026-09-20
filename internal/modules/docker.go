package modules

import (
	"context"
	"strings"

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
	if host.OS.Family == "opensuse" && host.PackageManager == "zypper" {
		return planOpenSUSEDocker(host, cfg)
	}
	if host.OS.Family == "arch" && host.PackageManager == "pacman" {
		return planArchDocker(host, cfg)
	}
	if host.OS.Family == "alpine" && host.PackageManager == "apk" {
		return planAlpineDocker(host, cfg)
	}
	if host.OS.Family == "void" && host.PackageManager == "xbps" {
		return planVoidDocker(host, cfg)
	}
	if host.OS.Family == "devuan" && host.PackageManager == "apt" {
		return planDevuanDocker(host, cfg)
	}
	if host.OS.Family == "artix" && host.PackageManager == "pacman" {
		return planArtixDocker(host, cfg)
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

const devuanDockerPackagesAvailableScript = `for package in docker.io docker-compose; do
  candidate=$(LC_ALL=C apt-cache policy "$package" 2>/dev/null | awk '/^[[:space:]]*Candidate:/ { print $2; exit }')
  test -n "$candidate" && test "$candidate" != '(none)' || exit 1
  LC_ALL=C apt-cache madison "$package" 2>/dev/null | awk -v version="$candidate" '
    $3 == version { seen=1; if ($5 != "http://deb.devuan.org/merged" || $6 !~ /^excalibur(-updates|-security)?\//) bad=1; else good=1 }
    END { exit !(seen && good && !bad) }'
done`

func planDevuanDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete
	changes := []plan.Change{}
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed Devuan Docker package set is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "docker.io or docker-compose is not installed", Desired: "Devuan Excalibur docker.io and Docker Compose v2 packages installed", Preconditions: []plan.Precondition{{ID: "docker.devuan-packages-available", Description: "the current APT candidate versions are exclusively from Devuan Excalibur merged repositories", Script: devuanDockerPackagesAvailableScript}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "devuan-excalibur", Script: "export DEBIAN_FRONTEND=noninteractive\napt-get install -y docker.io docker-compose"}, Verification: "reviewed Devuan Docker packages are installed"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the current APT candidates are not exclusively from reviewed Devuan Excalibur merged repositories; Bebop will not use a shadowing repository"
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
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: "the package-provided Docker SysVinit service is disabled, inactive, or unresponsive", Risk: plan.Privileged, RequiresRoot: true, Current: "Docker SysVinit service not ready", Desired: "Docker enabled in SysV multi-user runlevels and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "devuan", Script: sysvEnableAndStartScript("docker")}, Verification: "package-provided Docker SysVinit service is enabled and docker info succeeds as root"}
		if needEngine && changes[0].Blocked != "" {
			change.Action.Script, change.Blocked = "", "Devuan Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

const artixDockerPackagesAvailableScript = `for package in docker docker-compose docker-dinit; do
  LC_ALL=C pacman -Si "world/$package" 2>/dev/null | awk -F ' *: *' '$1 == "Repository" { found=($2 == "world") } END { exit !found }' || exit 1
done`

func planArtixDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !host.Docker.CgroupsAvailable {
		return []plan.Change{{ID: "docker.cgroups", Module: "docker", Summary: "review Artix cgroup support", Reason: "Docker requires a usable cgroup hierarchy", Risk: plan.Privileged, RequiresRoot: true, Current: "cgroup hierarchy unavailable", Desired: "usable Linux cgroup hierarchy", Action: plan.Action{Kind: "docker.cgroups-blocked", Resource: "artix"}, Verification: "not applicable", Blocked: "Artix Docker support requires a usable cgroup hierarchy; Bebop will not rewrite kernel or cgroup configuration"}}, nil, nil
	}
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete
	changes := []plan.Change{}
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed Artix Docker package set is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "docker, docker-compose, or docker-dinit is not installed", Desired: "official Artix world Docker packages and dinit integration installed", Preconditions: []plan.Precondition{{ID: "docker.artix-packages-available", Description: "the existing Pacman sync database advertises reviewed Artix world packages", Script: artixDockerPackagesAvailableScript}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "artix-world", Script: "pacman -S --needed --noconfirm world/docker world/docker-compose world/docker-dinit"}, Verification: "reviewed Artix Docker packages and packaged dinit service are installed"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the current Pacman sync database does not advertise reviewed Artix world Docker packages; perform a reviewed full Artix upgrade manually and retry (Bebop never runs pacman -Sy)"
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
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: "the packaged Artix dockerd dinit service is disabled, inactive, or unresponsive", Risk: plan.Privileged, RequiresRoot: true, Current: "dockerd dinit service not ready", Desired: "dockerd persistently enabled through dinit and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "artix", Script: dinitEnableAndStartScript("dockerd")}, Verification: "packaged dockerd dinit service is enabled and docker info succeeds as root"}
		if host.Docker.Installed && !host.Docker.ServiceDefinition {
			change.Action.Script, change.Blocked = "", "the installed Artix Docker package set does not provide the reviewed /etc/dinit.d/dockerd service; Bebop will not create a replacement"
		} else if needEngine && changes[0].Blocked != "" {
			change.Action.Script, change.Blocked = "", "Artix Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

const alpineDockerRepositorySafeScript = `if test -e /etc/apk/repositories.d/50-bebop.list; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community' /etc/apk/repositories.d/50-bebop.list
  test "$(grep -Ec '^(# Managed by Bebop\\. Manual edits may be replaced\\.|v2( @bebop-(main|community))? https://dl-cdn\\.alpinelinux\\.org/alpine/v3\\.24 (main|community))$' /etc/apk/repositories.d/50-bebop.list)" -eq 5
fi`

const alpineDockerInstallScript = `set -eu
if test -e /etc/apk/repositories.d/50-bebop.list; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main' /etc/apk/repositories.d/50-bebop.list
  grep -Fqx 'v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community' /etc/apk/repositories.d/50-bebop.list
  test "$(grep -Ec '^(# Managed by Bebop\\. Manual edits may be replaced\\.|v2( @bebop-(main|community))? https://dl-cdn\\.alpinelinux\\.org/alpine/v3\\.24 (main|community))$' /etc/apk/repositories.d/50-bebop.list)" -eq 5
fi
install -d -m 0755 /etc/apk/repositories.d
tmp=$(mktemp /etc/apk/repositories.d/.50-bebop.list.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main
v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community
v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main
v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/apk/repositories.d/50-bebop.list
trap - EXIT
apk --interactive=no update --repositories-file /etc/apk/repositories.d/50-bebop.list
apk --interactive=no add --repositories-file /etc/apk/repositories.d/50-bebop.list docker@bebop-community docker-cli-compose@bebop-community docker-openrc@bebop-community`

func planAlpineDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	changes := []plan.Change{}
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete || host.Docker.RepositoryState != "managed"
	if !host.Docker.CgroupsAvailable {
		return []plan.Change{{ID: "docker.cgroups", Module: "docker", Summary: "review Alpine cgroup support", Reason: "Docker requires a usable cgroup v2 hierarchy", Risk: plan.Privileged, RequiresRoot: true, Current: "cgroup v2 hierarchy unavailable", Desired: "usable Alpine cgroup v2 hierarchy", Action: plan.Action{Kind: "docker.cgroups-blocked", Resource: "alpine"}, Verification: "not applicable", Blocked: "Alpine Docker support requires a usable cgroup v2 hierarchy; Bebop will not rewrite a custom cgroup configuration"}}, nil, nil
	}
	if host.Docker.CgroupsServiceExists && (!host.Docker.CgroupsServiceEnabled || !host.Docker.CgroupsServiceActive) {
		change := plan.Change{ID: "docker.cgroups", Module: "docker", Summary: "enable Alpine cgroups", Reason: "the OpenRC cgroups service is disabled or inactive", Risk: plan.Privileged, RequiresRoot: true, Current: "cgroups service not ready", Desired: "cgroups enabled in OpenRC default runlevel and running", Action: plan.Action{Kind: "docker.enable-cgroups", Resource: "alpine", Script: "rc-update add cgroups default\nrc-service cgroups start"}, Verification: "cgroups OpenRC service is enabled and running"}
		rootBlocked(&change, host.SudoAvailable)
		changes = append(changes, change)
	}
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed Alpine Docker package set or repository definition is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "docker, docker-cli-compose, docker-openrc, or Bebop's v3.24 repository file is absent", Desired: "reviewed Alpine v3.24 community Docker packages installed", Preconditions: []plan.Precondition{{ID: "docker.alpine-repository-safe", Description: "Bebop's APK repository definition is absent or exact", Script: alpineDockerRepositorySafeScript}, {ID: "docker.alpine-packages-available", Description: "the official Alpine v3.24 community repository advertises the reviewed Docker package set", Script: "for package in docker docker-cli-compose docker-openrc; do apk policy \"$package\" 2>/dev/null | grep -Fq 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' || exit 1; done"}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "alpine", Script: alpineDockerInstallScript}, Verification: "reviewed Alpine Docker package set and repository definition are installed"}
		if host.Docker.RepositoryState == "unmanaged" {
			change.Action.Script = ""
			change.Blocked = "existing /etc/apk/repositories.d/50-bebop.list is not Bebop-managed; review it manually before Bebop can take ownership"
		} else if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the target's official Alpine v3.24 community repository does not advertise the reviewed Docker package set"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
		dependencies := []string(nil)
		if host.Docker.CgroupsServiceExists && (!host.Docker.CgroupsServiceEnabled || !host.Docker.CgroupsServiceActive) {
			dependencies = append(dependencies, "docker.cgroups")
		}
		if needEngine {
			dependencies = append(dependencies, "docker.engine")
		}
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: "OpenRC Docker service is disabled, inactive, or daemon unresponsive", Risk: plan.Privileged, RequiresRoot: true, Current: "Docker OpenRC service not ready", Desired: "Docker enabled in default runlevel, running, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "alpine", Script: "rc-update add docker default\nrc-service docker start"}, Verification: "Docker OpenRC service is enabled and docker info succeeds as root"}
		if needEngine && len(changes) > 0 && changes[len(changes)-1].ID == "docker.engine" && changes[len(changes)-1].Blocked != "" {
			change.Blocked = "Alpine Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

func voidPackagesAvailableScript(repository string, packages ...string) string {
	script := ""
	for _, pkg := range packages {
		script += "xbps-query --ignore-conf-repos --repository=" + transport.ShellQuote(repository) + " -M -S " + transport.ShellQuote(pkg) + " >/dev/null\n"
	}
	return script
}

const voidDockerHoldSafetyScript = `! xbps-query -H 2>/dev/null | grep -Eq '(^|[[:space:]])(docker|docker-compose)([<>=~][^[:space:]]*)?([[:space:]]|$)'
! xbps-query --list-repolock-pkgs 2>/dev/null | grep -Eq '(^|[[:space:]])(docker|docker-compose)([<>=~][^[:space:]]*)?([[:space:]]|$)'`

func voidPackageProvenanceSafetyScript(repository string, packages ...string) string {
	var script strings.Builder
	for _, pkg := range packages {
		script.WriteString("if xbps-query -p pkgver ")
		script.WriteString(transport.ShellQuote(pkg))
		script.WriteString(" >/dev/null 2>&1; then xbps-query -p repository ")
		script.WriteString(transport.ShellQuote(pkg))
		script.WriteString(" 2>/dev/null | grep -Fqx ")
		script.WriteString(transport.ShellQuote(repository))
		script.WriteString("; fi\n")
	}
	return script.String()
}

func voidPackageInstallScript(repository string, packages ...string) string {
	quoted := make([]string, 0, len(packages))
	for _, pkg := range packages {
		quoted = append(quoted, transport.ShellQuote(pkg))
	}
	return "xbps-install -S -y --ignore-conf-repos --repository=" + transport.ShellQuote(repository) + " " + strings.Join(quoted, " ") + " </dev/null"
}

func planVoidDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	repository, reviewed := facts.VoidRepository(host.Architecture, host.Libc)
	if !reviewed {
		return []plan.Change{{ID: "docker.engine", Module: "docker", Summary: "review Void package repository", Reason: "the target architecture/libc has no reviewed Void package mapping", Risk: plan.Privileged, RequiresRoot: true, Current: "unreviewed Void package source", Desired: "reviewed official Void package source", Action: plan.Action{Kind: "docker.install-engine", Resource: "void"}, Verification: "not applicable", Blocked: "Bebop does not have a reviewed official Void repository mapping for this architecture/libc combination"}}, nil, nil
	}
	if host.Docker.RepositoryState == "unmanaged" {
		return []plan.Change{{ID: "docker.engine", Module: "docker", Summary: "review installed Docker provenance", Reason: "an installed Docker package was not recorded from the reviewed Void repository", Risk: plan.Privileged, RequiresRoot: true, Current: "unmanaged Docker package provenance", Desired: "reviewed official Void Docker packages", Action: plan.Action{Kind: "docker.install-engine", Resource: "void"}, Verification: "not applicable", Blocked: "Bebop will not adopt an installed Docker package whose XBPS repository is not the reviewed official Void repository"}}, nil, nil
	}
	if host.Docker.PackageHeld || host.Docker.PackageRepolocked {
		return []plan.Change{{ID: "docker.engine", Module: "docker", Summary: "review held Docker packages", Reason: "a required Docker package is held or repolocked", Risk: plan.Privileged, RequiresRoot: true, Current: "XBPS hold or repolock prevents reviewed Docker convergence", Desired: "operator-reviewed package constraints", Action: plan.Action{Kind: "docker.install-engine", Resource: "void"}, Verification: "not applicable", Blocked: "Bebop will not override an XBPS hold or repolock for docker or docker-compose; review the package constraint manually"}}, nil, nil
	}
	if !host.Docker.CgroupsAvailable {
		return []plan.Change{{ID: "docker.cgroups", Module: "docker", Summary: "review Void cgroup support", Reason: "Docker requires a usable cgroup hierarchy", Risk: plan.Privileged, RequiresRoot: true, Current: "cgroup hierarchy unavailable", Desired: "usable Linux cgroups", Action: plan.Action{Kind: "docker.cgroups-blocked", Resource: "void"}, Verification: "not applicable", Blocked: "Void Docker support requires a usable cgroup hierarchy; Bebop will not rewrite kernel or cgroup configuration"}}, nil, nil
	}
	changes := []plan.Change{}
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed Void Docker package set is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "docker or docker-compose is not installed", Desired: "official Void docker and docker-compose packages installed", Preconditions: []plan.Precondition{{ID: "docker.void-packages-available", Description: "the reviewed official Void repository advertises Docker packages", Script: voidPackagesAvailableScript(repository, "docker", "docker-compose")}, {ID: "docker.void-package-provenance", Description: "any installed Docker package came from the reviewed official Void repository", Script: voidPackageProvenanceSafetyScript(repository, "docker", "docker-compose")}, {ID: "docker.void-package-constraints", Description: "required Docker packages are not held or repolocked", Script: voidDockerHoldSafetyScript}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "void", Script: voidPackageInstallScript(repository, "docker", "docker-compose")}, Verification: "reviewed official Void Docker packages are installed"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the reviewed official Void repository does not advertise docker and docker-compose for this target; Bebop will not use another repository"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Docker.ServiceEnabled || !host.Docker.ServiceActive || !host.Docker.Responsive {
		dependencies := []string(nil)
		if needEngine {
			dependencies = append(dependencies, "docker.engine")
		}
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: "runit Docker service is disabled, inactive, or daemon unresponsive", Risk: plan.Privileged, RequiresRoot: true, Current: "Docker runit service not ready", Desired: "Docker enabled under runit, running, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "void", Script: runitEnableAndStartScript("docker")}, Verification: "Docker runit service link is correct and docker info succeeds as root"}
		if host.Docker.ServiceLinkState == "conflict" {
			change.Action.Script = ""
			change.Blocked = "existing /var/service/docker does not point exactly to the package-provided /etc/sv/docker; Bebop will not replace it"
		} else if !needEngine && !host.Docker.ServiceDefinition {
			change.Action.Script = ""
			change.Blocked = "the installed Void Docker package does not provide /etc/sv/docker; Bebop will not create a replacement service definition"
		} else if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script = ""
			change.Blocked = "Void Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if len(cfg.Services) > 0 && !host.Docker.ComposeAvailable && !needEngine {
		change := plan.Change{ID: "docker.compose", Module: "docker", Summary: "install Docker Compose v2", Reason: "docker compose is unavailable", Risk: plan.Privileged, RequiresRoot: true, Current: "Compose v2 unavailable", Desired: "Docker Compose v2 available for managed services", Dependencies: []string{"docker.service"}, Action: plan.Action{Kind: "docker.install-compose", Resource: "void", Script: voidPackageInstallScript(repository, "docker-compose")}, Verification: "docker compose version succeeds"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the reviewed official Void repository does not advertise docker-compose for this target"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

const archDockerPackagesAvailableScript = `LC_ALL=C pacman -Si docker 2>/dev/null | awk -F ' *: *' 'function finish() { if (name != "") { if (name == "docker" && (repository == "core" || repository == "extra" || repository == "multilib")) count++; else invalid=1; name=""; repository="" } } $1 == "Repository" { finish(); repository=$2 } $1 == "Name" { name=$2 } END { finish(); exit !(count == 1 && !invalid) }'
LC_ALL=C pacman -Si docker-compose 2>/dev/null | awk -F ' *: *' 'function finish() { if (name != "") { if (name == "docker-compose" && (repository == "core" || repository == "extra" || repository == "multilib")) count++; else invalid=1; name=""; repository="" } } $1 == "Repository" { finish(); repository=$2 } $1 == "Name" { name=$2 } END { finish(); exit !(count == 1 && !invalid) }'`

// planArchDocker intentionally uses Pacman's already-synchronized database.
// It must not add -y or turn capability installation into a system upgrade:
// Arch does not support partial upgrades, and full upgrades remain explicit
// operator work.
func planArchDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	changes := []plan.Change{}
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed Arch Docker package set is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "docker or docker-compose is not installed", Desired: "official Arch docker and docker-compose packages installed", Preconditions: []plan.Precondition{{ID: "docker.arch-packages-available", Description: "the existing Pacman sync database advertises the reviewed official packages", Script: archDockerPackagesAvailableScript}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "arch", Script: "pacman -S --needed --noconfirm docker docker-compose"}, Verification: "official Arch Docker packages are installed"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "the current Pacman sync database does not advertise the reviewed docker and docker-compose packages; perform a reviewed full pacman -Syu manually and retry (Bebop never runs pacman -Sy)"
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
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: "service disabled, inactive, or daemon unresponsive", Risk: plan.Privileged, RequiresRoot: true, Current: "docker.service is not ready", Desired: "docker.service enabled, active, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "arch", Script: "systemctl enable --now docker.service"}, Verification: "docker.service is enabled and docker info succeeds as root"}
		if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Blocked = "Arch Docker package installation is blocked"
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
		change := plan.Change{ID: "docker.compose", Module: "docker", Summary: "install Docker Compose v2", Reason: "docker compose is unavailable", Risk: plan.Privileged, RequiresRoot: true, Current: "Compose v2 unavailable", Desired: "Docker Compose v2 available for managed services", Dependencies: dependencies, Action: plan.Action{Kind: "docker.install-compose", Resource: "arch", Script: "pacman -S --needed --noconfirm docker-compose"}, Verification: "docker compose version succeeds"}
		if host.Docker.ComposePackageAvailable != "docker-compose" {
			change.Action.Script = ""
			change.Blocked = "the current Pacman sync database does not advertise official Arch docker-compose; perform a reviewed full pacman -Syu manually and retry"
		} else if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script = ""
			change.Blocked = "Arch Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

func planOpenSUSEDocker(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if host.Docker.ConflictingPackages {
		return []plan.Change{{ID: "docker.conflict", Module: "docker", Summary: "review conflicting Docker packages", Reason: "an incompatible external Docker CE package is installed", Risk: plan.Privileged, RequiresRoot: true, Current: "external Docker CE package installed", Desired: "reviewed openSUSE docker and docker-compose packages", Action: plan.Action{Kind: "docker.conflict", Resource: "opensuse"}, Verification: "external Docker CE packages are absent", Blocked: "openSUSE Docker support will not mix its reviewed distribution packages with an existing Docker CE stack; resolve it manually before apply"}}, nil, nil
	}
	changes := []plan.Change{}
	needEngine := !host.Docker.Installed || !host.Docker.PackageSetComplete
	if needEngine {
		change := plan.Change{ID: "docker.engine", Module: "docker", Summary: "install Docker Engine", Reason: "the reviewed openSUSE Docker package set is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "docker or docker-compose is not installed", Desired: "openSUSE docker and docker-compose packages installed", Preconditions: []plan.Precondition{{ID: "docker.no-external-conflict", Description: "external Docker CE packages are still absent", Script: openSUSEDockerNoConflictScript}}, Action: plan.Action{Kind: "docker.install-engine", Resource: "opensuse", Script: "zypper --non-interactive install docker docker-compose"}, Verification: "reviewed openSUSE Docker packages are installed"}
		if !host.Docker.PackageSetAvailable {
			change.Action.Script = ""
			change.Blocked = "enabled official openSUSE repositories do not advertise the reviewed docker and docker-compose package set"
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
		change := plan.Change{ID: "docker.service", Module: "docker", Summary: "enable and start Docker", Reason: "service disabled, inactive, or daemon unresponsive", Risk: plan.Privileged, RequiresRoot: true, Current: "docker.service is not ready", Desired: "docker.service enabled, active, and responsive", Dependencies: dependencies, Action: plan.Action{Kind: "docker.enable-service", Resource: "opensuse", Script: "systemctl enable --now docker.service"}, Verification: "docker.service is enabled and docker info succeeds as root"}
		if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Blocked = "openSUSE Docker package installation is blocked"
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
		change := plan.Change{ID: "docker.compose", Module: "docker", Summary: "install Docker Compose v2", Reason: "docker compose is unavailable", Risk: plan.Privileged, RequiresRoot: true, Current: "Compose v2 unavailable", Desired: "Docker Compose v2 available for managed services", Dependencies: dependencies, Action: plan.Action{Kind: "docker.install-compose", Resource: "opensuse", Script: "zypper --non-interactive install docker-compose"}, Verification: "docker compose version succeeds"}
		if host.Docker.ComposePackageAvailable != "docker-compose" {
			change.Action.Script = ""
			change.Blocked = "enabled official openSUSE repositories do not advertise docker-compose"
		} else if needEngine && len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script = ""
			change.Blocked = "openSUSE Docker package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	return changes, nil, nil
}

const openSUSEDockerNoConflictScript = `for package in docker-ce docker-ce-cli docker-compose-plugin; do
  if rpm -q "$package" >/dev/null 2>&1; then exit 1; fi
done`

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
		if change.Action.Resource == "void" {
			return verify(ctx, tr, "xbps-query -p pkgver docker >/dev/null\nxbps-query -p pkgver docker-compose >/dev/null")
		}
		if change.Action.Resource == "alpine" {
			return verify(ctx, tr, "apk info -e docker docker-cli-compose docker-openrc >/dev/null\n"+alpineDockerRepositorySafeScript)
		}
		if change.Action.Resource == "arch" {
			return verify(ctx, tr, "pacman -Q docker docker-compose >/dev/null")
		}
		if change.Action.Resource == "artix-world" {
			return verify(ctx, tr, "pacman -Q docker docker-compose docker-dinit >/dev/null")
		}
		if change.Action.Resource == "devuan-excalibur" {
			return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' docker.io docker-compose | grep -qx installed\n"+devuanDockerPackagesAvailableScript)
		}
		if change.Action.Resource == "opensuse" {
			return verify(ctx, tr, "rpm -q docker docker-compose >/dev/null")
		}
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
	if change.Action.Resource == "void" {
		return verify(ctx, tr, runitServiceReadyScript("docker")+"\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null")
	}
	if change.Action.Resource == "devuan" {
		return verify(ctx, tr, sysvServiceReadyScript("docker")+"\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null")
	}
	if change.Action.Resource == "artix" {
		return verify(ctx, tr, dinitServiceReadyScript("dockerd")+"\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null")
	}
	if change.Action.Kind == "docker.enable-cgroups" {
		return verify(ctx, tr, "test -r /sys/fs/cgroup/cgroup.controllers\nrc-update show default | grep -Eq '^[[:space:]]*cgroups([[:space:]]|$)'\nrc-service cgroups status >/dev/null")
	}
	if change.Action.Resource == "alpine" {
		return verify(ctx, tr, "rc-update show default | grep -Eq '^[[:space:]]*docker([[:space:]]|$)'\nrc-service docker status >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null")
	}
	return verify(ctx, tr, "systemctl is-enabled docker.service >/dev/null\nsystemctl is-active docker.service >/dev/null\nenv -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null")
}
