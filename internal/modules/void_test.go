package modules

import (
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
)

func voidHost(architecture, libc string) facts.HostFacts {
	return facts.HostFacts{
		OS:                facts.OS{ID: "void", Family: "void", Supported: true},
		Architecture:      architecture,
		ArchitectureKnown: true,
		Libc:              libc,
		PackageManager:    "xbps",
		InitSystem:        facts.InitSystemRunit,
		SudoAvailable:     true,
		RequiredTools:     facts.RequiredTools{Flock: true, LSBLK: true, Findmnt: true},
		RootMode:          "persistent",
		DataRoot:          facts.Directory{Path: config.DefaultDataRoot, Exists: true, Mode: "750"},
	}
}

func TestVoidDockerUsesReviewedXBPSRepositoryAndSafeRunitLifecycle(t *testing.T) {
	for _, test := range []struct{ architecture, libc, repository string }{
		{"amd64", "glibc", "https://repo-default.voidlinux.org/current"},
		{"amd64", "musl", "https://repo-default.voidlinux.org/current/musl"},
		{"arm64", "glibc", "https://repo-default.voidlinux.org/current/aarch64"},
		{"arm64", "musl", "https://repo-default.voidlinux.org/current/aarch64"},
	} {
		host := voidHost(test.architecture, test.libc)
		host.Docker.PackageSetAvailable, host.Docker.CgroupsAvailable = true, true
		changes, _, err := (Docker{}).Plan(host, config.Defaults())
		if err != nil || len(changes) < 2 {
			t.Fatalf("Void Docker plan for %s/%s = %#v, %v", test.architecture, test.libc, changes, err)
		}
		combined := changes[0].Action.Script + "\n" + changes[0].Preconditions[0].Script + "\n" + changes[1].Action.Script
		for _, required := range []string{"xbps-install -S -y --ignore-conf-repos", test.repository, "'docker' 'docker-compose' </dev/null", "/etc/sv/docker", "ln -s '/etc/sv/docker' '/var/service/docker'", "sv up 'docker'"} {
			if !strings.Contains(combined, required) {
				t.Fatalf("Void Docker plan missing %q: %s", required, combined)
			}
		}
		for _, forbidden := range []string{"xbps-install -Su", "xbps-install -u", "curl | sh", "docker-ce", "ln -sf", "/var/lib/docker", "--force", "SSL_NO_VERIFY"} {
			if strings.Contains(combined, forbidden) {
				t.Fatalf("Void Docker plan contains unsafe %q: %s", forbidden, combined)
			}
		}
	}
	host := voidHost("amd64", "glibc")
	host.Docker.PackageSetAvailable, host.Docker.CgroupsAvailable, host.Docker.PackageHeld = true, true, true
	changes, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("held Void Docker package was not blocked: %#v, %v", changes, err)
	}
	host.Docker.PackageHeld, host.Docker.PackageSetAvailable, host.Docker.ServiceLinkState = false, true, "conflict"
	changes, _, err = (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) < 2 || changes[1].Blocked == "" || changes[1].Action.Script != "" {
		t.Fatalf("conflicting Void Docker service link was not blocked: %#v, %v", changes, err)
	}
}

func TestVoidTailscaleUsesOfficialPackageAndSafeRunitLifecycle(t *testing.T) {
	host := voidHost("amd64", "musl")
	host.Tailscale.PackageAvailable = true
	changes, warnings, err := (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(changes) < 2 || len(warnings) != 0 {
		t.Fatalf("Void Tailscale plan = %#v %#v %v", changes, warnings, err)
	}
	combined := changes[0].Action.Script + "\n" + changes[0].Preconditions[0].Script + "\n" + changes[1].Action.Script
	for _, required := range []string{"https://repo-default.voidlinux.org/current/musl", "xbps-install -S -y --ignore-conf-repos", "'tailscale' </dev/null", "/etc/sv/tailscaled", "sv up 'tailscaled'"} {
		if !strings.Contains(combined, required) {
			t.Fatalf("Void Tailscale plan missing %q: %s", required, combined)
		}
	}
	for _, forbidden := range []string{"tailscale up", "curl | sh", "--force", "ln -sf", "SSL_NO_VERIFY"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("Void Tailscale plan contains unsafe %q: %s", forbidden, combined)
		}
	}
	host.Tailscale.PackageHeld = true
	changes, _, err = (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || changes[0].Blocked == "" {
		t.Fatalf("held Void Tailscale package was not blocked: %#v, %v", changes, err)
	}
}

func TestVoidAutomaticUpdatesAreExplicitlyBlocked(t *testing.T) {
	host := voidHost("amd64", "glibc")
	changes, _, err := (Updates{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].Blocked == "" || changes[0].Action.Script != "" || !strings.Contains(changes[0].Blocked, "xbps-install -Su") {
		t.Fatalf("Void automatic updates were not explicitly blocked: %#v, %v", changes, err)
	}
	cfg := config.Defaults()
	cfg.Features.AutomaticUpdates = false
	changes, _, err = (Updates{}).Plan(host, cfg)
	if err != nil || len(changes) != 0 {
		t.Fatalf("Void with automatic updates disabled did not plan normally: %#v, %v", changes, err)
	}
}

func TestVoidSSHUsesRunitRestartWithoutChangingPackageConfig(t *testing.T) {
	host := voidHost("amd64", "glibc")
	host.EffectiveUser = "void"
	host.SSH = facts.SSH{Installed: true, Service: "runit:sshd", ServiceEnabled: true, ServiceActive: true, ConfigValid: true, DropInSupported: true, FirstDropIn: "99-void.conf", AuthorizedKeysPresent: true}
	changes, _, err := (SSH{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].Blocked != "" {
		t.Fatalf("Void SSH plan = %#v, %v", changes, err)
	}
	if !strings.Contains(changes[0].Action.Script, "sv restart sshd") || strings.Contains(changes[0].Action.Script, "99-void.conf") || strings.Contains(changes[0].Action.Script, "/etc/ssh/sshd_config\n") {
		t.Fatalf("Void SSH action did not preserve drop-ins/runit behavior: %#v", changes[0])
	}
	host.SSH.ServiceActive = false
	changes, _, err = (SSH{}).Plan(host, config.Defaults())
	if err != nil || changes[0].Blocked == "" {
		t.Fatalf("inactive Void sshd did not block hardening before mutation: %#v, %v", changes, err)
	}
}
