package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Tailscale struct{}

func (Tailscale) Name() string { return "tailscale" }

const tailscaleOpenSUSESigningKeyFingerprint = "2596A99EAAB33821893C0A79458CA832957F5868"

func (Tailscale) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.Tailscale {
		return nil, nil, nil
	}
	if host.OS.Family == "alpine" && host.PackageManager == "apk" {
		return planAlpineTailscale(host)
	}
	if (host.PackageManager == "dnf5" || (host.OS.Family == "enterprise-linux" && host.PackageManager == "dnf") || (host.OS.Family == "opensuse" && host.PackageManager == "zypper")) && host.Tailscale.RepositoryState == "unmanaged" {
		platform := "Fedora"
		resource := "fedora"
		if host.PackageManager == "dnf" {
			platform = "Enterprise Linux"
			if family, major, ok := facts.TailscaleRPMRepositoryPolicy(host.OS); ok {
				resource = family + "-" + major
			}
		}
		if host.PackageManager == "zypper" {
			platform, resource = "openSUSE", "opensuse"
		}
		return []plan.Change{{ID: "tailscale.repository", Module: "tailscale", Summary: "review Tailscale repository ownership", Reason: "an unmanaged " + platform + " Tailscale repository definition exists", Risk: plan.Privileged, RequiresRoot: true, Current: "unmanaged /etc/yum.repos.d/tailscale.repo", Desired: "Bebop-reviewed signed repository configuration", Action: plan.Action{Kind: "tailscale.repository-conflict", Resource: resource}, Verification: "not applicable until repository ownership is resolved", Blocked: "Bebop will not accept an unmanaged Tailscale repository definition on " + platform + "; review it manually before enabling Tailscale management"}}, nil, nil
	}
	changes := []plan.Change{}
	warnings := []plan.Warning{}
	needsRPMRepository := (host.PackageManager == "dnf5" || (host.OS.Family == "enterprise-linux" && host.PackageManager == "dnf") || (host.OS.Family == "opensuse" && host.PackageManager == "zypper")) && host.Tailscale.RepositoryState != "managed"
	if !host.Tailscale.Installed || needsRPMRepository {
		if host.PackageManager == "dnf5" {
			change := fedoraTailscaleChange(host)
			changes = append(changes, change)
		} else if host.OS.Family == "enterprise-linux" && host.PackageManager == "dnf" {
			changes = append(changes, enterpriseTailscaleChange(host))
		} else if host.OS.Family == "opensuse" && host.PackageManager == "zypper" {
			changes = append(changes, openSUSETailscaleChange(host))
		} else if host.OS.Family == "arch" && host.PackageManager == "pacman" {
			changes = append(changes, archTailscaleChange(host))
		} else if distribution, codename, ok := tailscaleRepository(host.OS); !ok {
			changes = append(changes, plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed package repository", Action: plan.Action{Kind: "tailscale.install", Resource: host.OS.ID}, Verification: "tailscale package is installed", Blocked: "Bebop does not have a reviewed Tailscale repository mapping for " + host.OS.Display()})
		} else {
			change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed package repository", Preconditions: []plan.Precondition{{ID: "tailscale.package-absent", Description: "tailscale is still not installed", Script: "! dpkg-query -W -f='${db:Status-Status}' tailscale 2>/dev/null | grep -qx installed"}}, Action: plan.Action{Kind: "tailscale.install", Resource: distribution + "/" + codename, Script: tailscaleInstallScript(distribution, codename)}, Verification: "tailscale package is installed"}
			rootBlocked(&change, host.SudoAvailable)
			changes = append(changes, change)
		}
	}
	if host.Tailscale.Installed && (!host.Tailscale.ServiceEnabled || !host.Tailscale.ServiceActive) {
		change := plan.Change{ID: "tailscale.service", Module: "tailscale", Summary: "enable and start Tailscale", Reason: "tailscaled.service is disabled or inactive", Risk: plan.Privileged, RequiresRoot: true, Current: "disabled or inactive", Desired: "tailscaled.service enabled and active", Action: plan.Action{Kind: "tailscale.enable-service", Script: "systemctl enable --now tailscaled.service"}, Verification: "tailscaled.service is enabled and active"}
		rootBlocked(&change, host.SudoAvailable)
		changes = append(changes, change)
	} else if !host.Tailscale.Installed {
		// The service must follow successful package installation, even though it
		// did not exist at inspection time.
		change := plan.Change{ID: "tailscale.service", Module: "tailscale", Summary: "enable and start Tailscale", Reason: "tailscaled.service will be provided by the package", Risk: plan.Privileged, RequiresRoot: true, Current: "unavailable until package install", Desired: "tailscaled.service enabled and active", Dependencies: []string{"tailscale.package"}, Action: plan.Action{Kind: "tailscale.enable-service", Script: "systemctl enable --now tailscaled.service"}, Verification: "tailscaled.service is enabled and active"}
		if changes[0].Blocked != "" {
			change.Blocked = "Tailscale package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if host.Tailscale.Installed && !host.Tailscale.Connected {
		warnings = append(warnings, plan.Warning{ID: "tailscale.authentication", Module: "tailscale", Summary: "Tailscale is installed but this node is not authenticated", Resolution: "Run on the target: sudo tailscale up"})
	}
	return changes, warnings, nil
}

func planAlpineTailscale(host facts.HostFacts) ([]plan.Change, []plan.Warning, error) {
	changes := []plan.Change{}
	needPackage := !host.Tailscale.Installed || host.Tailscale.RepositoryState != "managed"
	if needPackage {
		change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "the reviewed Alpine Tailscale package set or repository definition is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "tailscale, tailscale-openrc, or Bebop's v3.24 repository file is absent", Desired: "official Alpine v3.24 community Tailscale and OpenRC packages installed", Preconditions: []plan.Precondition{{ID: "tailscale.alpine-repository-safe", Description: "Bebop's APK repository definition is absent or exact", Script: alpineDockerRepositorySafeScript}, {ID: "tailscale.alpine-package-available", Description: "the official Alpine v3.24 community repository advertises Tailscale", Script: "for package in tailscale tailscale-openrc; do apk policy \"$package\" 2>/dev/null | grep -Fq 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' || exit 1; done"}}, Action: plan.Action{Kind: "tailscale.install", Resource: "alpine", Script: alpineTailscaleInstallScript}, Verification: "Tailscale and its Alpine OpenRC package are installed"}
		if host.Tailscale.RepositoryState == "unmanaged" {
			change.Action.Script = ""
			change.Blocked = "existing /etc/apk/repositories.d/50-bebop.list is not Bebop-managed; review it manually before Bebop can take ownership"
		} else if !host.Tailscale.PackageAvailable {
			change.Action.Script = ""
			change.Blocked = "the target's official Alpine v3.24 community repository does not advertise tailscale and tailscale-openrc"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Tailscale.ServiceEnabled || !host.Tailscale.ServiceActive {
		dependencies := []string(nil)
		if needPackage {
			dependencies = append(dependencies, "tailscale.package")
		}
		change := plan.Change{ID: "tailscale.service", Module: "tailscale", Summary: "enable and start Tailscale", Reason: "Alpine Tailscale OpenRC service is disabled or inactive", Risk: plan.Privileged, RequiresRoot: true, Current: "tailscale OpenRC service not ready", Desired: "Tailscale enabled in default runlevel and active", Dependencies: dependencies, Action: plan.Action{Kind: "tailscale.enable-service", Resource: "alpine", Script: "rc-update add tailscale default\nrc-service tailscale start"}, Verification: "Tailscale OpenRC service is enabled and active"}
		if len(changes) > 0 && changes[0].Blocked != "" {
			change.Blocked = "Tailscale package installation is blocked"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	warnings := []plan.Warning{}
	if host.Tailscale.Installed && !host.Tailscale.Connected {
		warnings = append(warnings, plan.Warning{ID: "tailscale.authentication", Module: "tailscale", Summary: "Tailscale is installed but this node is not authenticated", Resolution: "Run on the target: sudo tailscale up"})
	}
	return changes, warnings, nil
}

const alpineTailscaleInstallScript = `set -eu
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
apk --interactive=no add --repositories-file /etc/apk/repositories.d/50-bebop.list tailscale@bebop-community tailscale-openrc@bebop-community`

const archTailscalePackageAvailableScript = "LC_ALL=C pacman -Si tailscale 2>/dev/null | awk -F ' *: *' 'function finish() { if (name != \"\") { if (name == \"tailscale\" && (repository == \"core\" || repository == \"extra\" || repository == \"multilib\")) count++; else invalid=1; name=\"\"; repository=\"\" } } $1 == \"Repository\" { finish(); repository=$2 } $1 == \"Name\" { name=$2 } END { finish(); exit !(count == 1 && !invalid) }'"

func archTailscaleChange(host facts.HostFacts) plan.Change {
	change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "official Arch tailscale package installed", Preconditions: []plan.Precondition{{ID: "tailscale.package-absent", Description: "tailscale is still not installed", Script: "! pacman -Q tailscale >/dev/null 2>&1"}, {ID: "tailscale.arch-package-available", Description: "the existing Pacman sync database advertises the official tailscale package", Script: archTailscalePackageAvailableScript}}, Action: plan.Action{Kind: "tailscale.install", Resource: "arch", Script: "pacman -S --needed --noconfirm tailscale"}, Verification: "tailscale package is installed"}
	if !host.Tailscale.PackageAvailable {
		change.Action.Script = ""
		change.Blocked = "the current Pacman sync database does not advertise official Arch tailscale; perform a reviewed full pacman -Syu manually and retry (Bebop never runs pacman -Sy)"
	} else {
		rootBlocked(&change, host.SudoAvailable)
	}
	return change
}

func openSUSETailscaleChange(host facts.HostFacts) plan.Change {
	repository, ok := facts.OpenSUSETailscaleRepositoryPolicy(host.OS)
	if !ok {
		return plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed openSUSE repository", Action: plan.Action{Kind: "tailscale.install", Resource: "opensuse"}, Verification: "tailscale package is installed", Blocked: "Bebop does not have a reviewed Tailscale repository mapping for " + host.OS.Display()}
	}
	change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed openSUSE repository", Preconditions: []plan.Precondition{{ID: "tailscale.package-absent", Description: "tailscale is still not installed", Script: "! rpm -q tailscale >/dev/null 2>&1"}, {ID: "tailscale.repository-safe", Description: "the Tailscale repository is absent or Bebop-managed", Script: openSUSETailscaleRepositorySafeScript(repository)}}, Action: plan.Action{Kind: "tailscale.install", Resource: "opensuse", Script: openSUSETailscaleInstallScript(repository)}, Verification: "tailscale package is installed"}
	if host.Tailscale.RepositoryState == "unmanaged" {
		change.Action.Script = ""
		change.Blocked = "existing /etc/zypp/repos.d/tailscale.repo is not Bebop-managed; review it manually before Bebop can take ownership"
	} else {
		rootBlocked(&change, host.SudoAvailable)
	}
	return change
}

func openSUSETailscaleRepositorySafeScript(repository string) string {
	baseURL := "https://pkgs.tailscale.com/" + repository + "/$basearch"
	keyURL := "https://pkgs.tailscale.com/" + repository + "/repo.gpg"
	return `if test -e /etc/zypp/repos.d/tailscale.repo; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/zypp/repos.d/tailscale.repo
  grep -Fqx ` + transport.ShellQuote("baseurl="+baseURL) + ` /etc/zypp/repos.d/tailscale.repo
  grep -Fqx 'enabled=1' /etc/zypp/repos.d/tailscale.repo
  grep -Fqx 'gpgcheck=1' /etc/zypp/repos.d/tailscale.repo
  grep -Fqx 'repo_gpgcheck=1' /etc/zypp/repos.d/tailscale.repo
  grep -Fqx 'pkg_gpgcheck=1' /etc/zypp/repos.d/tailscale.repo
  grep -Fqx ` + transport.ShellQuote("gpgkey="+keyURL) + ` /etc/zypp/repos.d/tailscale.repo
fi
for candidate in /etc/zypp/repos.d/*.repo; do
  test -f "$candidate" || continue
  test "$candidate" = /etc/zypp/repos.d/tailscale.repo && continue
  ! grep -Fq 'pkgs.tailscale.com/stable/' "$candidate" 2>/dev/null
done`
}

func openSUSETailscaleInstallScript(repository string) string {
	baseURL := "https://pkgs.tailscale.com/" + repository + "/$basearch"
	keyURL := "https://pkgs.tailscale.com/" + repository + "/repo.gpg"
	return `set -eu
command -v curl >/dev/null 2>&1
command -v gpg >/dev/null 2>&1
key_tmp=$(mktemp /tmp/.bebop-tailscale-key.XXXXXX)
tmp=$(mktemp /etc/zypp/repos.d/.tailscale.repo.XXXXXX)
trap 'rm -f "$key_tmp" "$tmp"' EXIT
curl --fail --silent --show-error --location ` + transport.ShellQuote(keyURL) + ` --output "$key_tmp"
fingerprint=$(gpg --show-keys --with-colons "$key_tmp" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }')
test "$fingerprint" = ` + transport.ShellQuote(tailscaleOpenSUSESigningKeyFingerprint) + `
rpm --import "$key_tmp"
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[tailscale-stable]
name=Tailscale stable
baseurl=` + baseURL + `
enabled=1
autorefresh=1
type=rpm-md
gpgcheck=1
repo_gpgcheck=1
pkg_gpgcheck=1
gpgkey=` + keyURL + `
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/zypp/repos.d/tailscale.repo
rm -f "$key_tmp"
trap - EXIT
zypper --non-interactive install tailscale`
}

func enterpriseTailscaleChange(host facts.HostFacts) plan.Change {
	family, major, ok := facts.TailscaleRPMRepositoryPolicy(host.OS)
	if !ok {
		return plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed package repository", Action: plan.Action{Kind: "tailscale.install", Resource: "enterprise-linux"}, Verification: "tailscale package is installed", Blocked: "Bebop does not have a reviewed Tailscale RPM repository mapping for " + host.OS.Display()}
	}
	policy := family + "-" + major
	change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed Enterprise Linux repository", Preconditions: []plan.Precondition{{ID: "tailscale.package-absent", Description: "tailscale is still not installed", Script: "! rpm -q tailscale >/dev/null 2>&1"}, {ID: "tailscale.repository-safe", Description: "the Tailscale repository is absent or Bebop-managed", Script: enterpriseTailscaleRepositorySafeScript(family, major)}}, Action: plan.Action{Kind: "tailscale.install", Resource: policy, Script: enterpriseTailscaleInstallScript(family, major)}, Verification: "tailscale package is installed"}
	if host.Tailscale.RepositoryState == "unmanaged" {
		change.Action.Script = ""
		change.Blocked = "existing /etc/yum.repos.d/tailscale.repo is not Bebop-managed; review it manually before Bebop can take ownership"
	} else {
		rootBlocked(&change, host.SudoAvailable)
	}
	return change
}

func fedoraTailscaleChange(host facts.HostFacts) plan.Change {
	change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "Tailscale installed from its official signed Fedora repository", Preconditions: []plan.Precondition{{ID: "tailscale.package-absent", Description: "tailscale is still not installed", Script: "! rpm -q tailscale >/dev/null 2>&1"}, {ID: "tailscale.repository-safe", Description: "the Tailscale repository is absent or Bebop-managed", Script: "if test -e /etc/yum.repos.d/tailscale.repo; then grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/yum.repos.d/tailscale.repo; fi"}}, Action: plan.Action{Kind: "tailscale.install", Resource: "fedora", Script: fedoraTailscaleInstallScript}, Verification: "tailscale package is installed"}
	if host.Tailscale.RepositoryState == "unmanaged" {
		change.Action.Script = ""
		change.Blocked = "existing /etc/yum.repos.d/tailscale.repo is not Bebop-managed; review it manually before Bebop can take ownership"
	} else {
		rootBlocked(&change, host.SudoAvailable)
	}
	return change
}

const fedoraTailscaleInstallScript = `tmp=$(mktemp /etc/yum.repos.d/.tailscale.repo.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[tailscale-stable]
name=Tailscale stable
baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://pkgs.tailscale.com/stable/fedora/repo.gpg
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/yum.repos.d/tailscale.repo
trap - EXIT
dnf5 -y install tailscale`

func enterpriseTailscaleRepositorySafeScript(family, major string) string {
	baseURL := "https://pkgs.tailscale.com/stable/" + family + "/" + major + "/$basearch"
	keyURL := "https://pkgs.tailscale.com/stable/" + family + "/" + major + "/repo.gpg"
	return `if test -e /etc/yum.repos.d/tailscale.repo; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/yum.repos.d/tailscale.repo
  grep -Fqx ` + transport.ShellQuote("baseurl="+baseURL) + ` /etc/yum.repos.d/tailscale.repo
  grep -Fqx 'gpgcheck=1' /etc/yum.repos.d/tailscale.repo
  grep -Fqx 'repo_gpgcheck=1' /etc/yum.repos.d/tailscale.repo
  grep -Fqx ` + transport.ShellQuote("gpgkey="+keyURL) + ` /etc/yum.repos.d/tailscale.repo
fi
for candidate in /etc/yum.repos.d/*.repo; do
  test -f "$candidate" || continue
  test "$candidate" = /etc/yum.repos.d/tailscale.repo && continue
  ! grep -Fq 'pkgs.tailscale.com/stable/' "$candidate" 2>/dev/null
done`
}

func enterpriseTailscaleInstallScript(family, major string) string {
	baseURL := "https://pkgs.tailscale.com/stable/" + family + "/" + major + "/$basearch"
	keyURL := "https://pkgs.tailscale.com/stable/" + family + "/" + major + "/repo.gpg"
	return `tmp=$(mktemp /etc/yum.repos.d/.tailscale.repo.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[tailscale-stable]
name=Tailscale stable
baseurl=` + baseURL + `
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=` + keyURL + `
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/yum.repos.d/tailscale.repo
trap - EXIT
dnf -y install tailscale`
}

func (Tailscale) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "tailscale.install", "tailscale.enable-service")
}
func (Tailscale) Verify(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	if change.Action.Kind == "tailscale.install" {
		if change.Action.Resource == "alpine" {
			return verify(ctx, tr, "apk info -e tailscale tailscale-openrc >/dev/null\n"+alpineDockerRepositorySafeScript)
		}
		if change.Action.Resource == "arch" {
			return verify(ctx, tr, "pacman -Q tailscale >/dev/null")
		}
		if change.Action.Resource == "fedora" {
			return verify(ctx, tr, "rpm -q tailscale >/dev/null")
		}
		if strings.HasPrefix(change.Action.Resource, "centos-") || strings.HasPrefix(change.Action.Resource, "rhel-") {
			return verify(ctx, tr, "rpm -q tailscale >/dev/null")
		}
		if change.Action.Resource == "opensuse" {
			return verify(ctx, tr, "rpm -q tailscale >/dev/null")
		}
		return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' tailscale | grep -qx installed")
	}
	if change.Action.Resource == "alpine" {
		return verify(ctx, tr, "rc-update show default | grep -Eq '^[[:space:]]*tailscale([[:space:]]|$)'\nrc-service tailscale status >/dev/null")
	}
	return verify(ctx, tr, "systemctl is-enabled tailscaled.service >/dev/null\nsystemctl is-active tailscaled.service >/dev/null")
}

func tailscaleRepository(os facts.OS) (string, string, bool) {
	codename := os.VersionCodename
	if codename == "" {
		switch os.ID {
		case "debian", "raspbian":
			switch os.VersionID {
			case "12":
				codename = "bookworm"
			case "13":
				codename = "trixie"
			}
		case "ubuntu":
			switch os.VersionID {
			case "22.04":
				codename = "jammy"
			case "24.04":
				codename = "noble"
			}
		}
	}
	switch os.ID {
	case "debian", "raspbian":
		if codename == "bookworm" || codename == "trixie" {
			return "debian", codename, true
		}
	case "ubuntu":
		if codename == "jammy" || codename == "noble" {
			return "ubuntu", codename, true
		}
	}
	return "", "", false
}

func tailscaleInstallScript(distribution, codename string) string {
	base := fmt.Sprintf("https://pkgs.tailscale.com/stable/%s/%s", distribution, codename)
	return "export DEBIAN_FRONTEND=noninteractive\n" +
		"apt-get update\napt-get install -y ca-certificates curl\n" +
		"install -d -m 0755 /usr/share/keyrings\n" +
		"key_tmp=$(mktemp /usr/share/keyrings/.tailscale-key.XXXXXX)\n" +
		"list_tmp=$(mktemp /etc/apt/sources.list.d/.tailscale.XXXXXX)\n" +
		"trap 'rm -f \"$key_tmp\" \"$list_tmp\"' EXIT\n" +
		"curl --fail --silent --show-error --location " + transport.ShellQuote(base+".noarmor.gpg") + " --output \"$key_tmp\"\n" +
		"curl --fail --silent --show-error --location " + transport.ShellQuote(base+".list") + " --output \"$list_tmp\"\n" +
		"chown root:root \"$key_tmp\" \"$list_tmp\"\nchmod 0644 \"$key_tmp\" \"$list_tmp\"\n" +
		"mv -f \"$key_tmp\" /usr/share/keyrings/tailscale-archive-keyring.gpg\n" +
		"mv -f \"$list_tmp\" /etc/apt/sources.list.d/tailscale.list\ntrap - EXIT\n" +
		"apt-get update\napt-get install -y tailscale"
}
