package modules

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
)

func devuanHost() facts.HostFacts {
	return facts.HostFacts{OS: facts.OS{ID: "devuan", Family: "devuan", VersionID: "6", VersionCodename: "excalibur", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "apt", PackageDatabase: "dpkg", InitSystem: facts.InitSystemSysV, SudoAvailable: true, EffectiveUser: "devuan", RequiredTools: facts.RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, RootMode: "persistent", Docker: facts.Docker{PackageSetAvailable: true}, Tailscale: facts.Tailscale{RepositoryState: "absent"}, AutomaticUpdates: facts.AutomaticUpdates{PackageAvailable: true, ServiceExists: true, ConfigState: "absent"}}
}

func artixHost() facts.HostFacts {
	return facts.HostFacts{OS: facts.OS{ID: "artix", Family: "artix", BuildID: "rolling", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "pacman", InitSystem: facts.InitSystemDinit, SudoAvailable: true, EffectiveUser: "artix", RequiredTools: facts.RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, RootMode: "persistent", Docker: facts.Docker{PackageSetAvailable: true, CgroupsAvailable: true}, Tailscale: facts.Tailscale{PackageAvailable: true}}
}

func TestDevuanUsesReviewedAPTWithSysVinit(t *testing.T) {
	host := devuanHost()
	docker, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(docker) != 2 || docker[0].Blocked != "" || docker[1].Blocked != "" {
		t.Fatalf("Devuan Docker plan = %#v, %v", docker, err)
	}
	combined := docker[0].Preconditions[0].Script + "\n" + docker[0].Action.Script + "\n" + docker[1].Action.Script
	for _, required := range []string{"docker.io docker-compose", "deb.devuan.org/merged", "excalibur", "update-rc.d 'docker' defaults", "service 'docker' start"} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Devuan Docker plan missing %q: %s", required, combined)
		}
	}
	for _, forbidden := range []string{"deb.debian.org", "docker-ce", "curl | sh", "systemctl"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Devuan Docker plan contains unsafe %q: %s", forbidden, combined)
		}
	}

	tailscale, _, err := (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(tailscale) != 2 || tailscale[0].Blocked != "" || tailscale[1].Blocked != "" {
		t.Fatalf("Devuan Tailscale plan = %#v, %v", tailscale, err)
	}
	combined = tailscale[0].Action.Script + "\n" + tailscale[1].Action.Script
	for _, required := range []string{"stable/debian/trixie", devuanTailscaleKeySHA256, "start-stop-daemon", "/usr/sbin/tailscaled", "update-rc.d tailscaled defaults"} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Devuan Tailscale plan missing %q: %s", required, combined)
		}
	}
	for _, forbidden := range []string{"curl | sh", "tailscale up", ". /etc/default", "source /etc/default", "trusted=yes"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Devuan Tailscale action contains unsafe %q: %s", forbidden, combined)
		}
	}
	host.Tailscale.ServiceLinkState = "conflict"
	changes, _, err := (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 2 || changes[1].Blocked == "" || changes[1].Action.Script != "" {
		t.Fatalf("unmanaged Devuan tailscaled script was not blocked: %#v, %v", changes, err)
	}

	updates, _, err := (Updates{}).Plan(devuanHost(), config.Defaults())
	if err != nil || len(updates) != 1 || updates[0].Blocked != "" {
		t.Fatalf("Devuan updates plan = %#v, %v", updates, err)
	}
	for _, required := range []string{"unattended-upgrades cron", "o=Devuan,n=excalibur", "o=Devuan,n=excalibur-security", "/etc/cron.daily/apt-compat", "update-rc.d cron defaults"} {
		if !strings.Contains(updates[0].Action.Script, required) {
			t.Fatalf("Devuan automatic-update plan missing %q: %s", required, updates[0].Action.Script)
		}
	}
}

func TestArtixUsesReviewedPacmanWithDinit(t *testing.T) {
	host := artixHost()
	docker, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(docker) != 2 || docker[0].Blocked != "" || docker[1].Blocked != "" {
		t.Fatalf("Artix Docker plan = %#v, %v", docker, err)
	}
	combined := docker[0].Preconditions[0].Script + "\n" + docker[0].Action.Script + "\n" + docker[1].Action.Script
	for _, required := range []string{"world/docker", "world/docker-compose", "world/docker-dinit", "pacman -S --needed --noconfirm", "dinitctl -s enable 'dockerd'", "dinitctl -s start 'dockerd'"} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Artix Docker plan missing %q: %s", required, combined)
		}
	}
	for _, forbidden := range []string{"pacman -Sy", "pacman -Syu", "docker-ce", "yay", "paru", "ln -sf", "systemctl"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Artix Docker plan contains unsafe %q: %s", forbidden, combined)
		}
	}

	tailscale, _, err := (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(tailscale) != 2 || tailscale[0].Blocked != "" || tailscale[1].Blocked != "" {
		t.Fatalf("Artix Tailscale plan = %#v, %v", tailscale, err)
	}
	combined = tailscale[0].Action.Script + "\n" + tailscale[1].Action.Script
	for _, required := range []string{"world/tailscale", "world/tailscale-dinit", "dinitctl -s enable 'tailscaled'", "dinitctl -s start 'tailscaled'"} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Artix Tailscale plan missing %q: %s", required, combined)
		}
	}
	for _, forbidden := range []string{"pacman -Sy", "pacman -Syu", "tailscale up", "curl | sh", "dinitctl reload", "ln -sf"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Artix Tailscale plan contains unsafe %q: %s", forbidden, combined)
		}
	}

	updates, _, err := (Updates{}).Plan(host, config.Defaults())
	if err != nil || len(updates) != 1 || updates[0].Blocked == "" || updates[0].Action.Script != "" || !strings.Contains(updates[0].Blocked, "pacman -Syu") {
		t.Fatalf("Artix automatic updates were not explicitly blocked: %#v, %v", updates, err)
	}
	noUpdates := config.Defaults()
	noUpdates.Features.AutomaticUpdates = false
	updates, _, err = (Updates{}).Plan(host, noUpdates)
	if err != nil || len(updates) != 0 {
		t.Fatalf("Artix with automatic updates disabled did not plan normally: %#v, %v", updates, err)
	}
}

func TestSysVAndDinitActionsRemainShellValidAndSSHUsesSafeReloads(t *testing.T) {
	for _, script := range []string{sysvEnableAndStartScript("docker"), dinitEnableAndStartScript("dockerd"), devuanTailscaleSysVScript} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = bytes.NewBufferString(script)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid service script: %v\n%s\n%s", err, script, output)
		}
	}
	devuan := devuanHost()
	devuan.SSH = facts.SSH{Installed: true, Service: "sysv:ssh", ServiceEnabled: true, ServiceActive: true, ConfigValid: true, DropInSupported: true, FirstDropIn: "99-devuan.conf", AuthorizedKeysPresent: true}
	changes, _, err := (SSH{}).Plan(devuan, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].Blocked != "" || !strings.Contains(changes[0].Action.Script, "service ssh reload") {
		t.Fatalf("Devuan SSH plan = %#v, %v", changes, err)
	}
	artix := artixHost()
	artix.SSH = facts.SSH{Installed: true, Service: "dinit:sshd", ServiceEnabled: true, ServiceActive: true, ConfigValid: true, DropInSupported: true, FirstDropIn: "99-artix.conf", AuthorizedKeysPresent: true}
	changes, _, err = (SSH{}).Plan(artix, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].Blocked != "" || !strings.Contains(changes[0].Action.Script, "dinitctl -s signal HUP sshd") || strings.Contains(changes[0].Action.Script, "dinitctl reload") {
		t.Fatalf("Artix SSH plan = %#v, %v", changes, err)
	}
}
