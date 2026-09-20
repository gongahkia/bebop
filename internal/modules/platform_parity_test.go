package modules

import (
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/module"
	"github.com/bebop-home/bebop/internal/plan"
)

// TestPlatformParityRoutesEveryReviewedPlatform prevents a future matrix entry
// from silently reaching a package or service-manager fallback. Exact package
// atoms remain tested beside their module-specific policy.
func TestPlatformParityRoutesEveryReviewedPlatform(t *testing.T) {
	for _, policy := range facts.PlatformPolicies() {
		t.Run(policy.Key, func(t *testing.T) {
			host := parityHost(policy)
			cfg := config.Defaults()
			cfg.Features.AutomaticUpdates = false

			changes, _, err := (Docker{}).Plan(host, cfg)
			if err != nil || len(changes) == 0 || blockedChange(changes) {
				t.Fatalf("Docker route for %s = %#v, %v", policy.Key, changes, err)
			}
			changes, _, err = (Tailscale{}).Plan(host, cfg)
			if err != nil || len(changes) == 0 || blockedChange(changes) {
				t.Fatalf("Tailscale route for %s = %#v, %v", policy.Key, changes, err)
			}
			changes, _, err = (SSH{}).Plan(host, cfg)
			if err != nil || len(changes) != 1 || blockedChange(changes) {
				t.Fatalf("SSH lifecycle route for %s = %#v, %v", policy.Key, changes, err)
			}

			cfg.Features.Docker, cfg.Features.SSHHardening, cfg.Features.Tailscale = false, false, false
			cfg.Features.AutomaticUpdates = true
			changes, _, err = (Updates{}).Plan(host, cfg)
			if err != nil || len(changes) == 0 {
				t.Fatalf("automatic-update route for %s = %#v, %v", policy.Key, changes, err)
			}
			if policy.AutomaticUpdates == facts.AutomaticUpdatesUnsupported && !blockedChange(changes) {
				t.Fatalf("%s automatic updates were not explicitly blocked: %#v", policy.Key, changes)
			}
		})
	}
}

func TestDefaultModuleRegistryCoversPlatformParityCapabilities(t *testing.T) {
	registered := map[string]bool{}
	for _, current := range Default() {
		registered[current.Name()] = true
	}
	for _, name := range []string{"base", "updates", "docker", "tailscale", "ssh", "storage", "services"} {
		if !registered[name] {
			t.Fatalf("default module registry omitted %s", name)
		}
	}
	var _ []module.Module = Default()
}

func parityHost(policy facts.PlatformPolicy) facts.HostFacts {
	os := facts.OS{ID: policy.Match.ID, Name: policy.Match.Name, VersionID: policy.Match.VersionID, VersionCodename: policy.Match.VersionCodename, BuildID: policy.Match.BuildID, PlatformID: policy.Match.PlatformID, Family: policy.Family, Supported: true}
	if policy.Match.VersionPrefix != "" {
		os.VersionID = policy.Match.VersionPrefix + "2"
	}
	if policy.Key == "opensuse-tumbleweed" {
		os.VersionID = "20260920"
	}
	service := "ssh.service"
	switch policy.InitSystem {
	case facts.InitSystemOpenRC:
		service = "sshd"
	case facts.InitSystemRunit:
		service = "runit:sshd"
	case facts.InitSystemSysV:
		service = "sysv:ssh"
	case facts.InitSystemDinit:
		service = "dinit:sshd"
	}
	host := facts.HostFacts{
		OS: os, Architecture: policy.Architectures[0], ArchitectureKnown: true, PackageManager: policy.PackageManager, PackageDatabase: policy.PackageDatabase,
		InitSystem: policy.InitSystem, Systemd: policy.InitSystem == facts.InitSystemSystemd, EffectiveUser: "operator", SudoAvailable: true,
		RequiredTools: facts.RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, RootMode: "persistent",
		Docker:           facts.Docker{PackageSetAvailable: true, ComposePackageAvailable: "docker-compose", CgroupsAvailable: true, CgroupsServiceExists: true, CgroupsServiceEnabled: true, CgroupsServiceActive: true},
		Tailscale:        facts.Tailscale{PackageAvailable: true, RepositoryState: "absent"},
		SSH:              facts.SSH{Installed: true, Service: service, ServiceEnabled: true, ServiceActive: true, ConfigValid: true, DropInSupported: true, AuthorizedKeysPresent: true},
		AutomaticUpdates: facts.AutomaticUpdates{PackageAvailable: true, ServiceExists: true, ConfigState: "absent"},
	}
	if len(policy.Libcs) > 0 {
		host.Libc = policy.Libcs[0]
	}
	return host
}

func blockedChange(changes []plan.Change) bool {
	for _, change := range changes {
		if change.Blocked != "" {
			return true
		}
	}
	return false
}
