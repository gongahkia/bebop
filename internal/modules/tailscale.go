package modules

import (
	"context"
	"fmt"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Tailscale struct{}

func (Tailscale) Name() string { return "tailscale" }

func (Tailscale) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	if !cfg.Features.Tailscale {
		return nil, nil, nil
	}
	changes := []plan.Change{}
	warnings := []plan.Warning{}
	if !host.Tailscale.Installed {
		distribution, codename, ok := tailscaleRepository(host.OS)
		if !ok {
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

func (Tailscale) Apply(ctx context.Context, tr transport.Transport, change plan.Change) error {
	return runAction(ctx, tr, change, "tailscale.install", "tailscale.enable-service")
}
func (Tailscale) Verify(ctx context.Context, tr transport.Transport, change plan.Change) error {
	if change.Action.Kind == "tailscale.install" {
		return verify(ctx, tr, "dpkg-query -W -f='${db:Status-Status}' tailscale | grep -qx installed")
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
