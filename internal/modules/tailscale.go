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
	if host.OS.Family == "void" && host.PackageManager == "xbps" {
		return planVoidTailscale(host)
	}
	if host.OS.Family == "devuan" && host.PackageManager == "apt" {
		return planDevuanTailscale(host)
	}
	if host.OS.Family == "artix" && host.PackageManager == "pacman" {
		return planArtixTailscale(host)
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

const devuanTailscaleKeySHA256 = "3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39"

const devuanTailscaleDistroCandidates = `for package in ca-certificates curl; do
  candidate=$(LC_ALL=C apt-cache policy "$package" 2>/dev/null | awk '/^[[:space:]]*Candidate:/ { print $2; exit }')
  test -n "$candidate" && test "$candidate" != '(none)' || exit 1
  LC_ALL=C apt-cache madison "$package" 2>/dev/null | awk -v version="$candidate" '
    $3 == version { seen=1; if ($5 != "http://deb.devuan.org/merged" || $6 !~ /^excalibur(-updates|-security)?\//) bad=1; else good=1 }
    END { exit !(seen && good && !bad) }'
done`

const devuanTailscaleVendorCandidate = `candidate=$(LC_ALL=C apt-cache policy tailscale 2>/dev/null | awk '/^[[:space:]]*Candidate:/ { print $2; exit }')
test -n "$candidate" && test "$candidate" != '(none)'
LC_ALL=C apt-cache madison tailscale 2>/dev/null | awk -v version="$candidate" '
  $3 == version { seen=1; if ($5 != "https://pkgs.tailscale.com/stable/debian" || $6 !~ /^trixie\//) bad=1; else good=1 }
  END { exit !(seen && good && !bad) }'`

const devuanTailscaleRepositorySafeScript = `if test -e /etc/apt/sources.list.d/tailscale.list; then
  grep -Fqx 'deb https://pkgs.tailscale.com/stable/debian trixie main' /etc/apt/sources.list.d/tailscale.list
  test "$(grep -Evc '^[[:space:]]*(#.*)?$|^deb https://pkgs\.tailscale\.com/stable/debian trixie main$' /etc/apt/sources.list.d/tailscale.list)" = 0
fi
if test -e /usr/share/keyrings/tailscale-archive-keyring.gpg; then
  test "$(sha256sum /usr/share/keyrings/tailscale-archive-keyring.gpg | awk '{print $1}')" = ` + devuanTailscaleKeySHA256 + `
fi`

const devuanTailscaleInstallScript = `set -eu
` + devuanTailscaleRepositorySafeScript + `
` + devuanTailscaleDistroCandidates + `
export DEBIAN_FRONTEND=noninteractive
apt-get install -y ca-certificates curl
install -d -m 0755 /usr/share/keyrings /etc/apt/sources.list.d
key_tmp=$(mktemp /usr/share/keyrings/.tailscale-key.XXXXXX)
list_tmp=$(mktemp /etc/apt/sources.list.d/.tailscale.XXXXXX)
trap 'rm -f "$key_tmp" "$list_tmp"' EXIT
curl --fail --silent --show-error --location https://pkgs.tailscale.com/stable/debian/trixie.noarmor.gpg --output "$key_tmp"
test "$(sha256sum "$key_tmp" | awk '{print $1}')" = ` + devuanTailscaleKeySHA256 + `
printf '%s\n' 'deb https://pkgs.tailscale.com/stable/debian trixie main' >"$list_tmp"
chown root:root "$key_tmp" "$list_tmp"
chmod 0644 "$key_tmp" "$list_tmp"
if test -e /usr/share/keyrings/tailscale-archive-keyring.gpg; then
  test "$(sha256sum /usr/share/keyrings/tailscale-archive-keyring.gpg | awk '{print $1}')" = ` + devuanTailscaleKeySHA256 + `
else
  mv -f "$key_tmp" /usr/share/keyrings/tailscale-archive-keyring.gpg
fi
if test -e /etc/apt/sources.list.d/tailscale.list; then
  grep -Fqx 'deb https://pkgs.tailscale.com/stable/debian trixie main' /etc/apt/sources.list.d/tailscale.list
  test "$(grep -Evc '^[[:space:]]*(#.*)?$|^deb https://pkgs\.tailscale\.com/stable/debian trixie main$' /etc/apt/sources.list.d/tailscale.list)" = 0
else
  mv -f "$list_tmp" /etc/apt/sources.list.d/tailscale.list
fi
trap - EXIT
apt-get update
` + devuanTailscaleVendorCandidate + `
apt-get install -y tailscale`

const devuanTailscaleSysVScript = `set -eu
dpkg-query -S /usr/sbin/tailscaled | grep -Eq '^tailscale: /usr/sbin/tailscaled$'
if test -e /etc/init.d/tailscaled; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/init.d/tailscaled
fi
tmp=$(mktemp /etc/init.d/.tailscaled.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
#!/bin/sh
# Managed by Bebop. Manual edits may be replaced.
### BEGIN INIT INFO
# Provides:          tailscaled
# Required-Start:    $network $remote_fs
# Required-Stop:     $network $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Tailscale daemon
### END INIT INFO

DAEMON=/usr/sbin/tailscaled
PIDFILE=/run/tailscale/tailscaled.pid
STATE=/var/lib/tailscale/tailscaled.state
SOCKET=/run/tailscale/tailscaled.sock

case "$1" in
  start)
    install -d -o root -g root -m 0755 /run/tailscale
    install -d -o root -g root -m 0700 /var/lib/tailscale
    start-stop-daemon --start --quiet --oknodo --background --make-pidfile --pidfile "$PIDFILE" --exec "$DAEMON" -- --state="$STATE" --socket="$SOCKET"
    ;;
  stop)
    start-stop-daemon --stop --quiet --oknodo --pidfile "$PIDFILE" --exec "$DAEMON"
    rm -f "$PIDFILE"
    ;;
  restart)
    "$0" stop
    "$0" start
    ;;
  status)
    start-stop-daemon --status --pidfile "$PIDFILE" --exec "$DAEMON"
    ;;
  *)
    exit 2
    ;;
esac
EOF
chown root:root "$tmp"
chmod 0755 "$tmp"
sh -n "$tmp"
mv -f "$tmp" /etc/init.d/tailscaled
trap - EXIT
` + "\n" + `update-rc.d tailscaled defaults
service tailscaled start`

func planDevuanTailscale(host facts.HostFacts) ([]plan.Change, []plan.Warning, error) {
	changes := []plan.Change{}
	needPackage := !host.Tailscale.Installed || host.Tailscale.RepositoryState != "managed"
	if host.Tailscale.RepositoryState == "unmanaged" {
		return []plan.Change{{ID: "tailscale.package", Module: "tailscale", Summary: "review Tailscale repository ownership", Reason: "an unmanaged Tailscale Debian Trixie repository/keyring exists", Risk: plan.Privileged, RequiresRoot: true, Current: "unmanaged vendor repository state", Desired: "reviewed Trixie vendor repository", Action: plan.Action{Kind: "tailscale.install", Resource: "devuan-trixie"}, Verification: "not applicable", Blocked: "Bebop will not replace an unmanaged Tailscale repository definition or signing key; review it manually before enabling Devuan Tailscale management"}}, nil, nil
	}
	if needPackage {
		change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "the reviewed Tailscale package or Trixie vendor repository is absent", Risk: plan.Privileged, RequiresRoot: true, Current: "Tailscale or its reviewed Trixie vendor source is absent", Desired: "Tailscale installed from the reviewed Debian Trixie vendor repository", Preconditions: []plan.Precondition{{ID: "tailscale.devuan-repository-safe", Description: "the Tailscale repository/keyring is absent or exactly reviewed", Script: devuanTailscaleRepositorySafeScript}, {ID: "tailscale.devuan-distro-candidates", Description: "bootstrap dependencies resolve exclusively through Devuan Excalibur", Script: devuanTailscaleDistroCandidates}}, Action: plan.Action{Kind: "tailscale.install", Resource: "devuan-trixie", Script: devuanTailscaleInstallScript}, Verification: "tailscale is installed from the reviewed Debian Trixie vendor repository"}
		if host.Tailscale.RepositoryState == "managed" && !host.Tailscale.PackageAvailable {
			change.Action.Script = ""
			change.Blocked = "the reviewed Debian Trixie vendor repository does not advertise tailscale for this target; Bebop will not use another package source"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Tailscale.ServiceEnabled || !host.Tailscale.ServiceActive {
		dependencies := []string(nil)
		if needPackage {
			dependencies = []string{"tailscale.package"}
		}
		change := plan.Change{ID: "tailscale.service", Module: "tailscale", Summary: "enable and start Tailscale", Reason: "the Bebop-owned fixed Tailscale SysVinit wrapper is disabled or inactive", Risk: plan.Privileged, RequiresRoot: true, Current: "tailscaled SysVinit service not ready", Desired: "tailscaled enabled through SysVinit and active", Dependencies: dependencies, Action: plan.Action{Kind: "tailscale.enable-service", Resource: "devuan", Script: devuanTailscaleSysVScript}, Verification: "fixed Bebop-owned tailscaled SysVinit wrapper is enabled and active"}
		if host.Tailscale.ServiceLinkState == "conflict" {
			change.Action.Script, change.Blocked = "", "existing /etc/init.d/tailscaled is not Bebop-owned; Bebop will not replace an unmanaged service wrapper"
		} else if needPackage && len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script, change.Blocked = "", "Devuan Tailscale package installation is blocked"
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

const artixTailscalePackagesAvailableScript = `for package in tailscale tailscale-dinit; do
  LC_ALL=C pacman -Si "world/$package" 2>/dev/null | awk -F ' *: *' '$1 == "Repository" { found=($2 == "world") } END { exit !found }' || exit 1
done`

func planArtixTailscale(host facts.HostFacts) ([]plan.Change, []plan.Warning, error) {
	changes := []plan.Change{}
	needPackage := !host.Tailscale.Installed || !host.Tailscale.ServiceDefinition
	if needPackage {
		change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "the reviewed Artix Tailscale package set is incomplete", Risk: plan.Privileged, RequiresRoot: true, Current: "tailscale or tailscale-dinit is not installed", Desired: "official Artix world Tailscale package and packaged dinit integration installed", Preconditions: []plan.Precondition{{ID: "tailscale.artix-packages-available", Description: "the existing Pacman sync database advertises reviewed Artix world packages", Script: artixTailscalePackagesAvailableScript}}, Action: plan.Action{Kind: "tailscale.install", Resource: "artix-world", Script: "pacman -S --needed --noconfirm world/tailscale world/tailscale-dinit"}, Verification: "reviewed Artix Tailscale package and dinit service are installed"}
		if !host.Tailscale.PackageAvailable {
			change.Action.Script = ""
			change.Blocked = "the current Pacman sync database does not advertise reviewed Artix world Tailscale packages; perform a reviewed full Artix upgrade manually and retry (Bebop never runs pacman -Sy)"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Tailscale.ServiceEnabled || !host.Tailscale.ServiceActive {
		dependencies := []string(nil)
		if needPackage {
			dependencies = []string{"tailscale.package"}
		}
		change := plan.Change{ID: "tailscale.service", Module: "tailscale", Summary: "enable and start Tailscale", Reason: "the packaged Artix tailscaled dinit service is disabled or inactive", Risk: plan.Privileged, RequiresRoot: true, Current: "tailscaled dinit service not ready", Desired: "tailscaled persistently enabled through dinit and active", Dependencies: dependencies, Action: plan.Action{Kind: "tailscale.enable-service", Resource: "artix", Script: dinitEnableAndStartScript("tailscaled")}, Verification: "packaged tailscaled dinit service is enabled and active"}
		if host.Tailscale.Installed && !host.Tailscale.ServiceDefinition {
			change.Action.Script, change.Blocked = "", "the installed Artix Tailscale package does not provide the reviewed /etc/dinit.d/tailscaled service; Bebop will not create a replacement"
		} else if needPackage && len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script, change.Blocked = "", "Artix Tailscale package installation is blocked"
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

const voidTailscaleHoldSafetyScript = `! xbps-query -H 2>/dev/null | grep -Eq '(^|[[:space:]])tailscale([<>=~][^[:space:]]*)?([[:space:]]|$)'
! xbps-query --list-repolock-pkgs 2>/dev/null | grep -Eq '(^|[[:space:]])tailscale([<>=~][^[:space:]]*)?([[:space:]]|$)'`

func planVoidTailscale(host facts.HostFacts) ([]plan.Change, []plan.Warning, error) {
	repository, reviewed := facts.VoidRepository(host.Architecture, host.Libc)
	if !reviewed {
		return []plan.Change{{ID: "tailscale.package", Module: "tailscale", Summary: "review Void package repository", Reason: "the target architecture/libc has no reviewed Void package mapping", Risk: plan.Privileged, RequiresRoot: true, Current: "unreviewed Void package source", Desired: "reviewed official Void repository", Action: plan.Action{Kind: "tailscale.install", Resource: "void"}, Verification: "not applicable", Blocked: "Bebop does not have a reviewed official Void repository mapping for this architecture/libc combination"}}, nil, nil
	}
	if host.Tailscale.RepositoryState == "unmanaged" {
		return []plan.Change{{ID: "tailscale.package", Module: "tailscale", Summary: "review installed Tailscale provenance", Reason: "the installed Tailscale package was not recorded from the reviewed Void repository", Risk: plan.Privileged, RequiresRoot: true, Current: "unmanaged Tailscale package provenance", Desired: "reviewed official Void tailscale package", Action: plan.Action{Kind: "tailscale.install", Resource: "void"}, Verification: "not applicable", Blocked: "Bebop will not adopt an installed Tailscale package whose XBPS repository is not the reviewed official Void repository"}}, nil, nil
	}
	changes := []plan.Change{}
	if !host.Tailscale.Installed {
		change := plan.Change{ID: "tailscale.package", Module: "tailscale", Summary: "install Tailscale", Reason: "Tailscale is not installed", Risk: plan.Privileged, RequiresRoot: true, Current: "not installed", Desired: "official Void tailscale package installed", Preconditions: []plan.Precondition{{ID: "tailscale.void-package-available", Description: "the reviewed official Void repository advertises tailscale", Script: voidPackagesAvailableScript(repository, "tailscale")}, {ID: "tailscale.void-package-provenance", Description: "any installed Tailscale package came from the reviewed official Void repository", Script: voidPackageProvenanceSafetyScript(repository, "tailscale")}, {ID: "tailscale.void-package-constraints", Description: "tailscale is not held or repolocked", Script: voidTailscaleHoldSafetyScript}}, Action: plan.Action{Kind: "tailscale.install", Resource: "void", Script: voidPackageInstallScript(repository, "tailscale")}, Verification: "official Void tailscale package is installed"}
		if host.Tailscale.PackageHeld || host.Tailscale.PackageRepolocked {
			change.Action.Script = ""
			change.Blocked = "Bebop will not override an XBPS hold or repolock for tailscale; review the package constraint manually"
		} else if !host.Tailscale.PackageAvailable {
			change.Action.Script = ""
			change.Blocked = "the reviewed official Void repository does not advertise tailscale for this target; Bebop will not use another repository"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		changes = append(changes, change)
	}
	if !host.Tailscale.ServiceEnabled || !host.Tailscale.ServiceActive {
		dependencies := []string(nil)
		if !host.Tailscale.Installed {
			dependencies = append(dependencies, "tailscale.package")
		}
		change := plan.Change{ID: "tailscale.service", Module: "tailscale", Summary: "enable and start Tailscale", Reason: "runit Tailscale service is disabled or inactive", Risk: plan.Privileged, RequiresRoot: true, Current: "tailscaled runit service not ready", Desired: "tailscaled enabled under runit and active", Dependencies: dependencies, Action: plan.Action{Kind: "tailscale.enable-service", Resource: "void", Script: runitEnableAndStartScript("tailscaled")}, Verification: "tailscaled runit service link is correct and active"}
		if host.Tailscale.ServiceLinkState == "conflict" {
			change.Action.Script = ""
			change.Blocked = "existing /var/service/tailscaled does not point exactly to the package-provided /etc/sv/tailscaled; Bebop will not replace it"
		} else if host.Tailscale.Installed && !host.Tailscale.ServiceDefinition {
			change.Action.Script = ""
			change.Blocked = "the installed Void tailscale package does not provide /etc/sv/tailscaled; Bebop will not create a replacement service definition"
		} else if len(changes) > 0 && changes[0].Blocked != "" {
			change.Action.Script = ""
			change.Blocked = "Void Tailscale package installation is blocked"
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
		if change.Action.Resource == "void" {
			return verify(ctx, tr, "xbps-query -p pkgver tailscale >/dev/null")
		}
		if change.Action.Resource == "alpine" {
			return verify(ctx, tr, "apk info -e tailscale tailscale-openrc >/dev/null\n"+alpineDockerRepositorySafeScript)
		}
		if change.Action.Resource == "arch" {
			return verify(ctx, tr, "pacman -Q tailscale >/dev/null")
		}
		if change.Action.Resource == "artix-world" {
			return verify(ctx, tr, "pacman -Q tailscale tailscale-dinit >/dev/null")
		}
		if change.Action.Resource == "devuan-trixie" {
			return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' tailscale | grep -qx installed\n"+devuanTailscaleVendorCandidate)
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
	if change.Action.Resource == "void" {
		return verify(ctx, tr, runitServiceReadyScript("tailscaled"))
	}
	if change.Action.Resource == "devuan" {
		return verify(ctx, tr, "grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/init.d/tailscaled\n"+sysvServiceReadyScript("tailscaled"))
	}
	if change.Action.Resource == "artix" {
		return verify(ctx, tr, dinitServiceReadyScript("tailscaled"))
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
