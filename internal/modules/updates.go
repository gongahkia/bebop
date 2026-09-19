package modules

import (
	"context"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

const updatesScript = `export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y unattended-upgrades
tmp=$(mktemp /etc/apt/apt.conf.d/.52-bebop-auto-upgrades.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
// Managed by Bebop. Manual edits may be replaced.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/apt/apt.conf.d/52-bebop-auto-upgrades
trap - EXIT`

const fedoraUpdatesScript = `if test -e /etc/dnf/automatic.conf; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/dnf/automatic.conf
fi
dnf5 -y install dnf5-plugin-automatic
tmp=$(mktemp /etc/dnf/.automatic.conf.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[commands]
apply_updates = yes
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/dnf/automatic.conf
trap - EXIT
systemctl enable --now dnf5-automatic.timer`

const enterpriseUpdatesScript = `if test -e /etc/dnf/automatic.conf; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/dnf/automatic.conf
fi
for timer in dnf-automatic.timer dnf-automatic-download.timer dnf-automatic-notifyonly.timer; do
  if systemctl is-enabled "$timer" >/dev/null 2>&1 || systemctl is-active "$timer" >/dev/null 2>&1; then exit 1; fi
done
dnf -y install dnf-automatic
tmp=$(mktemp /etc/dnf/.automatic.conf.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[commands]
apply_updates = yes
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/dnf/automatic.conf
trap - EXIT
systemctl enable --now dnf-automatic-install.timer`

const openSUSELeapUpdatesScript = `set -eu
for file in /etc/systemd/system/bebop-zypper-patch.service /etc/systemd/system/bebop-zypper-patch.timer; do
  if test -e "$file"; then grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' "$file"; fi
done
if systemctl is-enabled os-update.timer >/dev/null 2>&1 || systemctl is-active os-update.timer >/dev/null 2>&1; then exit 1; fi
service_tmp=$(mktemp /etc/systemd/system/.bebop-zypper-patch.service.XXXXXX)
timer_tmp=$(mktemp /etc/systemd/system/.bebop-zypper-patch.timer.XXXXXX)
trap 'rm -f "$service_tmp" "$timer_tmp"' EXIT
cat >"$service_tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[Unit]
Description=Bebop openSUSE Leap patch updates

[Service]
Type=oneshot
ExecStart=/usr/bin/zypper --non-interactive refresh
ExecStart=/usr/bin/zypper --non-interactive patch
EOF
cat >"$timer_tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
[Unit]
Description=Bebop openSUSE Leap patch update schedule

[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
chown root:root "$service_tmp" "$timer_tmp"
chmod 0644 "$service_tmp" "$timer_tmp"
mv -f "$service_tmp" /etc/systemd/system/bebop-zypper-patch.service
mv -f "$timer_tmp" /etc/systemd/system/bebop-zypper-patch.timer
trap - EXIT
systemctl daemon-reload
systemctl enable --now bebop-zypper-patch.timer`

const openSUSETumbleweedUpdatesScript = `set -eu
if test -e /etc/os-update.conf; then
  grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/os-update.conf
fi
if systemctl is-enabled bebop-zypper-patch.timer >/dev/null 2>&1 || systemctl is-active bebop-zypper-patch.timer >/dev/null 2>&1; then exit 1; fi
zypper --non-interactive install os-update
tmp=$(mktemp /etc/.os-update.conf.XXXXXX)
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
UPDATE_CMD=dup
REBOOT_CMD=none
EOF
chown root:root "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" /etc/os-update.conf
trap - EXIT
systemctl enable --now os-update.timer`

const alpineAutomaticRepositoriesSafeScript = `set -eu
for repository_file in /etc/apk/repositories /etc/apk/repositories.d/*.list; do
  test -f "$repository_file" || continue
	while IFS= read -r line || test -n "$line"; do
		case "$line" in ''|'#'*) continue;; esac
		case "$line" in
		  'https://dl-cdn.alpinelinux.org/alpine/v3.24/main'|'https://dl-cdn.alpinelinux.org/alpine/v3.24/community'|'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main'|'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community'|'v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main'|'v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community') ;;
		  *) exit 1;;
		esac
  done < "$repository_file"
done`

const alpineUpdatesScript = `set -eu
` + alpineAutomaticRepositoriesSafeScript + `
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
apk --interactive=no add --repositories-file /etc/apk/repositories.d/50-bebop.list apk-cron@bebop-main
apk info -W /etc/periodic/daily/apk | grep -Fq 'apk-cron'
test -f /etc/periodic/daily/apk
if apk audit --details /etc/periodic/daily 2>/dev/null | grep -Fxq 'U etc/periodic/daily/apk'; then exit 1; fi
rc-update add crond default
rc-service crond start`

type Updates struct{}

func (Updates) Name() string { return "updates" }

func (Updates) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.AutomaticUpdates {
		return nil, nil, nil
	}
	if host.OS.Family == "arch" && host.PackageManager == "pacman" {
		return []plan.Change{{ID: "updates.unattended", Module: "updates", Summary: "review Arch rolling system upgrades", Reason: "automatic Arch system upgrades are deliberately unsupported", Risk: plan.Privileged, RequiresRoot: true, Current: "automatic updates requested", Desired: "operator-reviewed full Arch upgrades", Action: plan.Action{Kind: "updates.automatic-unsupported", Resource: "arch"}, Verification: "not applicable", Blocked: "Bebop deliberately does not automate Arch rolling system upgrades; perform a reviewed full pacman -Syu manually and retry without automatic_updates"}}, nil, nil
	}
	if host.OS.Family == "alpine" && host.PackageManager == "apk" {
		change := plan.Change{ID: "updates.unattended", Module: "updates", Summary: "enable automatic updates", Reason: "apk-cron or OpenRC crond is not ready", Risk: plan.Privileged, RequiresRoot: true, Current: "Alpine automatic updates disabled or unmanaged", Desired: "apk-cron applies same-branch Alpine v3.24 updates through OpenRC crond without reboot", Preconditions: []plan.Precondition{{ID: "updates.alpine-repositories-safe", Description: "all active APK repositories remain official Alpine v3.24 main/community", Script: alpineAutomaticRepositoriesSafeScript}}, Action: plan.Action{Kind: "updates.enable-unattended", Resource: "alpine", Script: alpineUpdatesScript}, Verification: "apk-cron is package-owned, active repositories are v3.24-only, and crond is enabled and running"}
		if host.AutomaticUpdates.ConfigState == "unmanaged" || host.Docker.RepositoryState == "unmanaged" {
			change.Action.Script = ""
			change.Blocked = "Alpine APK repository or apk-cron state is unmanaged or unsafe; Bebop will not enable automatic updates across an unreviewed repository policy"
		} else if !host.AutomaticUpdates.ServiceExists {
			change.Action.Script = ""
			change.Blocked = "Alpine automatic updates require the existing OpenRC crond service; Bebop will not install or replace a scheduler"
		} else if !host.AutomaticUpdates.PackageAvailable {
			change.Action.Script = ""
			change.Blocked = "the official Alpine v3.24 main repository does not advertise apk-cron"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		return []plan.Change{change}, nil, nil
	}
	managed := host.PackageManager != "dnf5" && host.PackageManager != "dnf" && host.PackageManager != "zypper" || host.AutomaticUpdates.ConfigState == "managed"
	if host.AutomaticUpdates.Installed && host.AutomaticUpdates.Enabled && managed && !host.AutomaticUpdates.ConflictingTimers {
		return nil, nil, nil
	}
	if host.PackageManager == "dnf5" {
		current := "dnf5-plugin-automatic is not installed"
		if host.AutomaticUpdates.Installed {
			current = "dnf5-plugin-automatic is installed but Bebop automatic updates are disabled"
		}
		change := plan.Change{ID: "updates.unattended", Module: "updates", Summary: "enable automatic updates", Reason: current, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "dnf5-plugin-automatic applies updates through the enabled dnf5-automatic.timer", Action: plan.Action{Kind: "updates.enable-unattended", Resource: "fedora", Script: fedoraUpdatesScript}, Verification: "dnf5 automatic configuration enables updates and its timer is active"}
		if host.AutomaticUpdates.ConfigState == "unmanaged" {
			change.Action.Script = ""
			change.Blocked = "existing /etc/dnf/automatic.conf is not Bebop-managed; review it manually before Bebop can take ownership"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		return []plan.Change{change}, nil, nil
	}
	if host.PackageManager == "dnf" {
		current := "dnf-automatic is not installed"
		if host.AutomaticUpdates.Installed {
			current = "dnf-automatic is installed but Bebop automatic updates are disabled"
		}
		change := plan.Change{ID: "updates.unattended", Module: "updates", Summary: "enable automatic updates", Reason: current, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "dnf-automatic applies updates through the enabled dnf-automatic-install.timer", Action: plan.Action{Kind: "updates.enable-unattended", Resource: "enterprise-linux", Script: enterpriseUpdatesScript}, Verification: "dnf automatic configuration enables updates and only Bebop's install timer is active"}
		if host.AutomaticUpdates.ConfigState == "unmanaged" {
			change.Action.Script = ""
			change.Blocked = "existing /etc/dnf/automatic.conf is not Bebop-managed; review it manually before Bebop can take ownership"
		} else if host.AutomaticUpdates.ConflictingTimers {
			change.Action.Script = ""
			change.Blocked = "another dnf-automatic timer is enabled or active; review and disable the competing automatic-update policy manually before Bebop manages updates"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		return []plan.Change{change}, nil, nil
	}
	if host.PackageManager == "zypper" && host.OS.Family == "opensuse" {
		mode, ok := facts.OpenSUSEUpdatePolicy(host.OS)
		if !ok {
			return nil, nil, nil
		}
		if mode == "leap" {
			change := plan.Change{ID: "updates.unattended", Module: "updates", Summary: "enable automatic updates", Reason: "Bebop's Leap patch timer is not enabled", Risk: plan.Privileged, RequiresRoot: true, Current: "Bebop patch update timer is absent or inactive", Desired: "Bebop-owned noninteractive zypper patch timer enabled without automatic reboot", Action: plan.Action{Kind: "updates.enable-unattended", Resource: "opensuse-leap", Script: openSUSELeapUpdatesScript}, Verification: "Bebop Leap patch timer is enabled and the fixed noninteractive patch service is installed"}
			if host.AutomaticUpdates.ConfigState == "unmanaged" {
				change.Action.Script = ""
				change.Blocked = "existing Bebop Leap update unit files are not Bebop-managed; review them manually before Bebop can take ownership"
			} else if host.AutomaticUpdates.ConflictingTimers {
				change.Action.Script = ""
				change.Blocked = "os-update.timer is enabled or active; review the competing automatic-update policy manually before Bebop manages Leap patches"
			} else {
				rootBlocked(&change, host.SudoAvailable)
			}
			return []plan.Change{change}, nil, nil
		}
		change := plan.Change{ID: "updates.unattended", Module: "updates", Summary: "enable automatic updates", Reason: "os-update is not configured for Tumbleweed distribution upgrades", Risk: plan.Privileged, RequiresRoot: true, Current: "os-update package, Bebop override, or timer is absent", Desired: "os-update performs noninteractive Tumbleweed dup updates with reboot disabled", Action: plan.Action{Kind: "updates.enable-unattended", Resource: "opensuse-tumbleweed", Script: openSUSETumbleweedUpdatesScript}, Verification: "os-update is configured for dup, reboot is disabled, and os-update.timer is active"}
		if host.AutomaticUpdates.ConfigState == "unmanaged" {
			change.Action.Script = ""
			change.Blocked = "existing /etc/os-update.conf is not Bebop-managed; review it manually before Bebop can take ownership"
		} else if host.AutomaticUpdates.ConflictingTimers {
			change.Action.Script = ""
			change.Blocked = "a Bebop Leap patch timer is enabled or active; remove the conflicting policy manually before Tumbleweed management"
		} else if !host.AutomaticUpdates.Installed && !host.AutomaticUpdates.PackageAvailable {
			change.Action.Script = ""
			change.Blocked = "enabled official openSUSE repositories do not advertise os-update; Bebop will not add another rolling-update scheduler"
		} else {
			rootBlocked(&change, host.SudoAvailable)
		}
		return []plan.Change{change}, nil, nil
	}
	current := "unattended-upgrades is not installed"
	if host.AutomaticUpdates.Installed {
		current = "unattended-upgrades is installed but automatic security updates are disabled"
	}
	change := plan.Change{ID: "updates.unattended", Module: "updates", Summary: "enable automatic security updates", Reason: current, Risk: plan.Privileged, RequiresRoot: true, Current: current, Desired: "unattended-upgrades installed with daily package-list and unattended-upgrade intervals", Action: plan.Action{Kind: "updates.enable-unattended", Script: updatesScript}, Verification: "apt effective configuration enables unattended upgrades"}
	rootBlocked(&change, host.SudoAvailable)
	return []plan.Change{change}, nil, nil
}

func (Updates) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "updates.enable-unattended")
}
func (Updates) Verify(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	if change.Action.Resource == "fedora" || change.Action.Script == fedoraUpdatesScript {
		return verify(ctx, tr, `rpm -q dnf5-plugin-automatic >/dev/null
grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/dnf/automatic.conf
grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/dnf/automatic.conf
systemctl is-enabled dnf5-automatic.timer >/dev/null
systemctl is-active dnf5-automatic.timer >/dev/null`)
	}
	if change.Action.Resource == "alpine" || change.Action.Script == alpineUpdatesScript {
		return verify(ctx, tr, `apk info -e apk-cron >/dev/null
apk info -W /etc/periodic/daily/apk | grep -Fq 'apk-cron'
test -f /etc/periodic/daily/apk
! apk audit --details /etc/periodic/daily 2>/dev/null | grep -Fxq 'U etc/periodic/daily/apk'
rc-update show default | grep -Eq '^[[:space:]]*crond([[:space:]]|$)'
rc-service crond status >/dev/null`+"\n"+alpineAutomaticRepositoriesSafeScript)
	}
	if change.Action.Resource == "enterprise-linux" || change.Action.Script == enterpriseUpdatesScript {
		return verify(ctx, tr, `rpm -q dnf-automatic >/dev/null
grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/dnf/automatic.conf
grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/dnf/automatic.conf
systemctl is-enabled dnf-automatic-install.timer >/dev/null
systemctl is-active dnf-automatic-install.timer >/dev/null
for timer in dnf-automatic.timer dnf-automatic-download.timer dnf-automatic-notifyonly.timer; do
  ! systemctl is-enabled "$timer" >/dev/null 2>&1
  ! systemctl is-active "$timer" >/dev/null 2>&1
done`)
	}
	if change.Action.Resource == "opensuse-leap" || change.Action.Script == openSUSELeapUpdatesScript {
		return verify(ctx, tr, `grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/systemd/system/bebop-zypper-patch.service
grep -Fqx 'ExecStart=/usr/bin/zypper --non-interactive refresh' /etc/systemd/system/bebop-zypper-patch.service
grep -Fqx 'ExecStart=/usr/bin/zypper --non-interactive patch' /etc/systemd/system/bebop-zypper-patch.service
systemctl is-enabled bebop-zypper-patch.timer >/dev/null
systemctl is-active bebop-zypper-patch.timer >/dev/null
! systemctl is-enabled os-update.timer >/dev/null 2>&1
! systemctl is-active os-update.timer >/dev/null 2>&1`)
	}
	if change.Action.Resource == "opensuse-tumbleweed" || change.Action.Script == openSUSETumbleweedUpdatesScript {
		return verify(ctx, tr, `rpm -q os-update >/dev/null
grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/os-update.conf
grep -Eq '^[[:space:]]*UPDATE_CMD[[:space:]]*=[[:space:]]*dup[[:space:]]*$' /etc/os-update.conf
grep -Eq '^[[:space:]]*REBOOT_CMD[[:space:]]*=[[:space:]]*none[[:space:]]*$' /etc/os-update.conf
systemctl is-enabled os-update.timer >/dev/null
systemctl is-active os-update.timer >/dev/null`)
	}
	return verify(ctx, tr, `dpkg-query -W -f='${db:Status-Status}' unattended-upgrades | grep -qx installed
apt-config dump | grep -Fqx 'APT::Periodic::Unattended-Upgrade "1";'
apt-config dump | grep -Fqx 'APT::Periodic::Update-Package-Lists "1";'`)
}
