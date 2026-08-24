package modules

import (
	"context"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

// SSHDropIn is normalized without a trailing newline because command-substitution
// based read-only probes trim line endings. The managed file is written with one.
const SSHDropIn = "# Managed by Bebop. Manual edits may be replaced.\nPermitRootLogin no\nPasswordAuthentication no"

type SSH struct{}

func (SSH) Name() string { return "ssh" }

func (SSH) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.SSHHardening {
		return nil, nil, nil
	}
	if !host.SSH.Installed {
		return nil, []plan.Warning{{ID: "ssh.hardening.unavailable", Module: "ssh", Summary: "SSH hardening is enabled but no SSH server is installed", Resolution: "Install and configure an SSH server separately, or set features.ssh_hardening = false."}}, nil
	}
	if host.SSH.BebopDropIn == SSHDropIn && host.SSH.HardeningEffective {
		return nil, nil, nil
	}
	current := "Bebop drop-in is absent or differs"
	if host.SSH.BebopDropIn == SSHDropIn && !host.SSH.HardeningEffective {
		current = "Bebop drop-in exists but PermitRootLogin/PasswordAuthentication are not effective"
	}
	change := plan.Change{ID: "ssh.hardening", Module: "ssh", Summary: "install conservative Bebop SSH hardening drop-in", Reason: current, Risk: plan.NetworkSensitive, RequiresRoot: true, Current: current, Desired: "effective PermitRootLogin no and PasswordAuthentication no in a validated Bebop-owned drop-in", Action: plan.Action{Kind: "ssh.write-hardening", Resource: "/etc/ssh/sshd_config.d/00-bebop.conf", Script: sshHardeningScript(host.SSH.Service)}, Verification: "sshd validates the resulting configuration, effective sshd -T values are hardened, and the managed drop-in matches desired content"}
	switch {
	case host.EffectiveUser == "root":
		change.Blocked = "the connected account is root; refusing PermitRootLogin no because Bebop cannot establish a separate non-root recovery path"
	case !host.SSH.AuthorizedKeysPresent:
		change.Blocked = "the connected target user has no non-empty ~/.ssh/authorized_keys; refusing to disable password authentication"
	case !host.SSH.ConfigValid:
		change.Blocked = "the current SSH configuration does not validate with sshd -t; refusing to install a hardening drop-in"
	case !host.SSH.DropInSupported:
		change.Blocked = "the current SSH configuration does not include /etc/ssh/sshd_config.d/*.conf; refusing to write an ineffective drop-in"
	case host.SSH.FirstDropIn != "" && host.SSH.FirstDropIn < "00-bebop.conf":
		change.Blocked = "an earlier SSH drop-in (" + host.SSH.FirstDropIn + ") could override Bebop's hardening; refusing to guess precedence"
	default:
		rootBlocked(&change, host.SudoAvailable)
	}
	return []plan.Change{change}, nil, nil
}

func (SSH) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "ssh.write-hardening")
}
func (SSH) Verify(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return verify(ctx, tr, "sshd -t\nsshd -T | grep -Fqx 'permitrootlogin no'\nsshd -T | grep -Fqx 'passwordauthentication no'\ntest \"$(cat /etc/ssh/sshd_config.d/00-bebop.conf)\" = \"$(printf '%s' '"+SSHDropIn+"')\"")
}

func sshHardeningScript(service string) string {
	reload := ""
	if service == "ssh.service" || service == "sshd.service" {
		reload = "\nsystemctl reload " + service
	}
	return `install -d -m 0755 /etc/ssh/sshd_config.d
	candidate=/etc/ssh/sshd_config.d/00-bebop-validate-$$.conf
trap 'rm -f "$candidate"' EXIT
cat >"$candidate" <<'EOF'
# Managed by Bebop. Manual edits may be replaced.
PermitRootLogin no
PasswordAuthentication no
EOF
chown root:root "$candidate"
chmod 0644 "$candidate"
sshd -t
sshd -T | grep -Fqx 'permitrootlogin no'
sshd -T | grep -Fqx 'passwordauthentication no'
mv -f "$candidate" /etc/ssh/sshd_config.d/00-bebop.conf
trap - EXIT
sshd -T | grep -Fqx 'permitrootlogin no'
sshd -T | grep -Fqx 'passwordauthentication no'` + reload
}
