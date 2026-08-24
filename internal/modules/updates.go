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

type Updates struct{}

func (Updates) Name() string { return "updates" }

func (Updates) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.AutomaticUpdates || (host.AutomaticUpdates.Installed && host.AutomaticUpdates.Enabled) {
		return nil, nil, nil
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
	return verify(ctx, tr, `dpkg-query -W -f='${db:Status-Status}' unattended-upgrades | grep -qx installed
apt-config dump | grep -Fqx 'APT::Periodic::Unattended-Upgrade "1";'
apt-config dump | grep -Fqx 'APT::Periodic::Update-Package-Lists "1";'`)
}
