package modules

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/apply"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/planner"
)

func fedoraHost() facts.HostFacts {
	return facts.HostFacts{OS: facts.OS{ID: "fedora", Family: "fedora", VersionID: "43", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf5", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: config.DefaultDataRoot, Exists: true, Mode: "750"}}
}

func enterpriseLinuxHost(id, version string) facts.HostFacts {
	os := facts.OS{ID: id, Family: "enterprise-linux", VersionID: version, Supported: true}
	if id == "centos" {
		os.Name = "CentOS Stream"
		os.PlatformID = "platform:el" + version
	}
	return facts.HostFacts{OS: os, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: config.DefaultDataRoot, Exists: true, Mode: "750"}}
}

func openSUSEHost(id, version string) facts.HostFacts {
	return facts.HostFacts{OS: facts.OS{ID: id, Family: "opensuse", VersionID: version, Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "zypper", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: config.DefaultDataRoot, Exists: true, Mode: "750"}}
}

func TestOpenSUSEDockerUsesOnlyReviewedDistributionPackages(t *testing.T) {
	host := openSUSEHost("opensuse-leap", "16.0")
	host.Docker.PackageSetAvailable = true
	changes, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) < 2 {
		t.Fatalf("openSUSE Docker plan = %#v, %v", changes, err)
	}
	script := changes[0].Action.Script
	for _, required := range []string{"zypper --non-interactive install docker docker-compose"} {
		if !strings.Contains(script, required) {
			t.Fatalf("openSUSE Docker script missing %q: %s", required, script)
		}
	}
	for _, forbidden := range []string{"docker-ce-stable", "curl | sh", "dnf", "OBS", "--no-gpg-checks", "--gpg-auto-import-keys", "/var/lib/docker"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("openSUSE Docker script contains forbidden %q: %s", forbidden, script)
		}
	}
	host.Docker.PackageSetAvailable = false
	changes, _, err = (Docker{}).Plan(host, config.Defaults())
	if err != nil || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("unavailable official Docker source was not blocked: %#v, %v", changes, err)
	}
	host.Docker.PackageSetAvailable, host.Docker.ConflictingPackages = true, true
	changes, _, err = (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].Blocked == "" || strings.Contains(changes[0].Action.Script, "remove") {
		t.Fatalf("external Docker CE conflict was not safely blocked: %#v, %v", changes, err)
	}
}

func TestOpenSUSEAutomaticUpdatesUseDistinctLeapAndTumbleweedPolicies(t *testing.T) {
	leap := openSUSEHost("opensuse-leap", "16.0")
	changes, _, err := (Updates{}).Plan(leap, config.Defaults())
	if err != nil || len(changes) != 1 {
		t.Fatalf("Leap update plan = %#v, %v", changes, err)
	}
	for _, required := range []string{"zypper --non-interactive refresh", "zypper --non-interactive patch", "bebop-zypper-patch.timer"} {
		if !strings.Contains(changes[0].Action.Script, required) {
			t.Fatalf("Leap update policy missing %q: %s", required, changes[0].Action.Script)
		}
	}
	if strings.Contains(changes[0].Action.Script, " dup") || strings.Contains(changes[0].Action.Script, "REBOOT_CMD=") {
		t.Fatalf("Leap update policy used rolling semantics: %s", changes[0].Action.Script)
	}
	tumbleweed := openSUSEHost("opensuse-tumbleweed", "20260122")
	tumbleweed.AutomaticUpdates.PackageAvailable = true
	changes, _, err = (Updates{}).Plan(tumbleweed, config.Defaults())
	if err != nil || len(changes) != 1 {
		t.Fatalf("Tumbleweed update plan = %#v, %v", changes, err)
	}
	for _, required := range []string{"zypper --non-interactive install os-update", "UPDATE_CMD=dup", "REBOOT_CMD=none", "os-update.timer"} {
		if !strings.Contains(changes[0].Action.Script, required) {
			t.Fatalf("Tumbleweed update policy missing %q: %s", required, changes[0].Action.Script)
		}
	}
	if strings.Contains(changes[0].Action.Script, "--auto-agree-with-licenses") || strings.Contains(changes[0].Action.Script, "--gpg-auto-import-keys") {
		t.Fatalf("Tumbleweed update policy weakened Zypper trust: %s", changes[0].Action.Script)
	}
	tumbleweed.AutomaticUpdates.ConfigState = "unmanaged"
	changes, _, err = (Updates{}).Plan(tumbleweed, config.Defaults())
	if err != nil || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("unmanaged Tumbleweed override was not blocked: %#v, %v", changes, err)
	}
	tumbleweed.AutomaticUpdates.ConfigState = "absent"
	tumbleweed.AutomaticUpdates.PackageAvailable = false
	changes, _, err = (Updates{}).Plan(tumbleweed, config.Defaults())
	if err != nil || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("unavailable Tumbleweed os-update package was not blocked: %#v, %v", changes, err)
	}
}

func TestOpenSUSETailscaleUsesReviewedRepositoryWithoutInstallScript(t *testing.T) {
	for _, test := range []struct{ id, version, path string }{{"opensuse-leap", "16.0", "stable/opensuse/leap/16.0"}, {"opensuse-tumbleweed", "20260916", "stable/opensuse/tumbleweed"}} {
		host := openSUSEHost(test.id, test.version)
		changes, _, err := (Tailscale{}).Plan(host, config.Defaults())
		if err != nil || len(changes) == 0 {
			t.Fatalf("openSUSE Tailscale plan = %#v, %v", changes, err)
		}
		script := changes[0].Action.Script
		for _, required := range []string{test.path + "/$basearch", "gpgcheck=1", "repo_gpgcheck=1", "pkg_gpgcheck=1", tailscaleOpenSUSESigningKeyFingerprint, "zypper --non-interactive install tailscale"} {
			if !strings.Contains(script, required) {
				t.Fatalf("openSUSE Tailscale script missing %q: %s", required, script)
			}
		}
		for _, forbidden := range []string{"curl | sh", "tailscale up", "--gpg-auto-import-keys", "--no-gpg-checks"} {
			if strings.Contains(script, forbidden) {
				t.Fatalf("openSUSE Tailscale script is unsafe: %s", script)
			}
		}
	}
}

func TestEnterpriseLinuxDockerUsesReviewedCERepositoriesAndPackages(t *testing.T) {
	tests := []struct {
		name, id, version, policy, repo string
	}{
		{"Rocky 9.8", "rocky", "9.8", "rhel-9", "https://download.docker.com/linux/rhel/9/$basearch/stable"},
		{"Rocky 10.2", "rocky", "10.2", "rhel-10", "https://download.docker.com/linux/rhel/10/$basearch/stable"},
		{"AlmaLinux 9.8", "almalinux", "9.8", "rhel-9", "https://download.docker.com/linux/rhel/9/$basearch/stable"},
		{"AlmaLinux 10.2", "almalinux", "10.2", "rhel-10", "https://download.docker.com/linux/rhel/10/$basearch/stable"},
		{"CentOS Stream 9", "centos", "9", "centos-9", "https://download.docker.com/linux/centos/9/$basearch/stable"},
		{"CentOS Stream 10", "centos", "10", "centos-10", "https://download.docker.com/linux/centos/10/$basearch/stable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			host := enterpriseLinuxHost(test.id, test.version)
			changes, _, err := (Docker{}).Plan(host, config.Defaults())
			if err != nil || len(changes) < 2 {
				t.Fatalf("EL Docker plan = %#v, %v", changes, err)
			}
			engine := changes[0]
			if engine.ID != "docker.engine" || engine.Action.Resource != test.policy {
				t.Fatalf("EL Docker policy = %#v", engine)
			}
			for _, required := range []string{test.repo, "gpgcheck=1", dockerCESigningKeyFingerprint, "dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin"} {
				if !strings.Contains(engine.Action.Script, required) {
					t.Fatalf("EL Docker script missing %q: %s", required, engine.Action.Script)
				}
			}
			for _, forbidden := range []string{"moby-engine", "dnf5", "curl | sh", "dnf remove", "podman", "/var/lib/docker"} {
				if strings.Contains(engine.Action.Script, forbidden) {
					t.Fatalf("EL Docker script contains forbidden %q: %s", forbidden, engine.Action.Script)
				}
			}
		})
	}
}

func TestEnterpriseLinuxDockerConflictsAndUnmanagedRepositoryBlock(t *testing.T) {
	host := enterpriseLinuxHost("rocky", "9.8")
	host.Docker.ConflictingPackages = true
	changes, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].ID != "docker.conflict" || changes[0].Blocked == "" || strings.Contains(changes[0].Action.Script, "remove") {
		t.Fatalf("EL Docker conflict was unsafe: %#v, %v", changes, err)
	}
	host.Docker.ConflictingPackages = false
	host.Docker.RepositoryState = "unmanaged"
	changes, _, err = (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].ID != "docker.repository" || changes[0].Blocked == "" {
		t.Fatalf("EL unmanaged Docker repository was accepted: %#v, %v", changes, err)
	}
	host.Docker.RepositoryState = "absent"
	host.Docker.Installed, host.Docker.PackageSetComplete = true, true
	changes, _, err = (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) == 0 || changes[0].ID != "docker.engine" || !strings.Contains(changes[0].Action.Script, "docker-ce-stable.repo") {
		t.Fatalf("existing Docker CE without reviewed repository was accepted: %#v, %v", changes, err)
	}
}

func TestEnterpriseLinuxAutomaticUpdatesUseDNFAutomatic(t *testing.T) {
	host := enterpriseLinuxHost("rocky", "9.8")
	changes, _, err := (Updates{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 {
		t.Fatalf("EL automatic-update plan = %#v, %v", changes, err)
	}
	script := changes[0].Action.Script
	for _, required := range []string{"dnf -y install dnf-automatic", "apply_updates = yes", "dnf-automatic-install.timer"} {
		if !strings.Contains(script, required) {
			t.Fatalf("EL automatic-update script missing %q: %s", required, script)
		}
	}
	if strings.Contains(script, "dnf5-plugin-automatic") {
		t.Fatalf("EL automatic-update script used Fedora package: %s", script)
	}
	host.AutomaticUpdates.ConfigState = "unmanaged"
	changes, _, err = (Updates{}).Plan(host, config.Defaults())
	if err != nil || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("EL unmanaged automatic-update config was not blocked: %#v, %v", changes, err)
	}
	host.AutomaticUpdates.ConfigState, host.AutomaticUpdates.ConflictingTimers = "absent", true
	changes, _, err = (Updates{}).Plan(host, config.Defaults())
	if err != nil || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("EL competing timers were not blocked: %#v, %v", changes, err)
	}
}

func TestEnterpriseLinuxTailscaleMappingsAreReviewed(t *testing.T) {
	tests := []struct{ id, version, path string }{
		{"rocky", "9.8", "stable/rhel/9/$basearch"}, {"rocky", "10.2", "stable/rhel/10/$basearch"},
		{"almalinux", "9.8", "stable/rhel/9/$basearch"}, {"almalinux", "10.2", "stable/rhel/10/$basearch"},
		{"centos", "9", "stable/centos/9/$basearch"}, {"centos", "10", "stable/centos/10/$basearch"},
	}
	for _, test := range tests {
		host := enterpriseLinuxHost(test.id, test.version)
		changes, _, err := (Tailscale{}).Plan(host, config.Defaults())
		if err != nil || len(changes) == 0 {
			t.Fatalf("EL Tailscale plan = %#v, %v", changes, err)
		}
		script := changes[0].Action.Script
		for _, required := range []string{test.path, "gpgcheck=1", "repo_gpgcheck=1", "dnf -y install tailscale"} {
			if !strings.Contains(script, required) {
				t.Fatalf("EL Tailscale script missing %q: %s", required, script)
			}
		}
		if strings.Contains(script, "curl") || strings.Contains(script, "| sh") || strings.Contains(script, "tailscale up") {
			t.Fatalf("EL Tailscale script is unsafe: %s", script)
		}
	}
	host := enterpriseLinuxHost("rocky", "9.8")
	host.Tailscale.Installed = true
	changes, _, err := (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(changes) == 0 || changes[0].ID != "tailscale.package" || !strings.Contains(changes[0].Action.Script, "stable/rhel/9/$basearch") {
		t.Fatalf("existing EL Tailscale package without reviewed repository was accepted: %#v, %v", changes, err)
	}
}

func TestFedoraDockerUsesOnlyReviewedMobyPackages(t *testing.T) {
	host := fedoraHost()
	host.Docker.PackageSetAvailable = true
	changes, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) < 2 {
		t.Fatalf("Fedora Docker plan = %#v, %v", changes, err)
	}
	engine := changes[0]
	if engine.ID != "docker.engine" || !strings.Contains(engine.Action.Script, "dnf5 -y install moby-engine docker-cli docker-compose") || strings.Contains(engine.Action.Script, "docker-ce") {
		t.Fatalf("Fedora Docker package choice is unsafe: %#v", engine)
	}
	host.Docker.ConflictingPackages = true
	changes, _, err = (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].ID != "docker.conflict" || changes[0].Blocked == "" {
		t.Fatalf("Docker CE conflict was not blocked: %#v, %v", changes, err)
	}
}

func TestDebianDockerPackagePlanRemainsAPTBased(t *testing.T) {
	host := facts.HostFacts{OS: facts.OS{ID: "debian", Family: "debian", VersionID: "12", Supported: true}, PackageManager: "apt", PackageDatabase: "dpkg", Systemd: true, SudoAvailable: true}
	changes, _, err := (Docker{}).Plan(host, config.Defaults())
	if err != nil || len(changes) == 0 || !strings.Contains(changes[0].Action.Script, "apt-get install -y docker.io") || strings.Contains(changes[0].Action.Script, "dnf5") {
		t.Fatalf("Debian Docker plan changed unexpectedly: %#v, %v", changes, err)
	}
}

func TestFedoraAutomaticUpdatesOwnsOnlyManagedConfiguration(t *testing.T) {
	host := fedoraHost()
	changes, _, err := (Updates{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || !strings.Contains(changes[0].Action.Script, "dnf5 -y install dnf5-plugin-automatic") || !strings.Contains(changes[0].Action.Script, "apply_updates = yes") || !strings.Contains(changes[0].Action.Script, "dnf5-automatic.timer") {
		t.Fatalf("Fedora automatic-update plan = %#v, %v", changes, err)
	}
	host.AutomaticUpdates.ConfigState = "unmanaged"
	changes, _, err = (Updates{}).Plan(host, config.Defaults())
	if err != nil || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("unmanaged DNF automatic configuration was not blocked: %#v, %v", changes, err)
	}
}

func TestFedoraTailscaleRepositoryIsReviewedAndNonInteractive(t *testing.T) {
	host := fedoraHost()
	changes, _, err := (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(changes) < 1 {
		t.Fatalf("Fedora Tailscale plan = %#v, %v", changes, err)
	}
	script := changes[0].Action.Script
	for _, required := range []string{"https://pkgs.tailscale.com/stable/fedora/$basearch", "gpgcheck=1", "repo_gpgcheck=1", "dnf5 -y install tailscale"} {
		if !strings.Contains(script, required) {
			t.Fatalf("Fedora Tailscale script missing %q: %s", required, script)
		}
	}
	if strings.Contains(script, "curl") || strings.Contains(script, "| sh") {
		t.Fatalf("Fedora Tailscale script uses an unsafe installer: %s", script)
	}
	host.Tailscale.RepositoryState = "unmanaged"
	changes, _, err = (Tailscale{}).Plan(host, config.Defaults())
	if err != nil || len(changes) != 1 || changes[0].ID != "tailscale.repository" || changes[0].Blocked == "" {
		t.Fatalf("unmanaged Tailscale repository was not blocked: %#v, %v", changes, err)
	}
}

func TestFedoraSELinuxRequiresSharedBindLabel(t *testing.T) {
	for _, test := range []struct {
		name, mount string
		blocked     bool
	}{
		{name: "shared", mount: "/srv/data:/data:rw,z"},
		{name: "plain", mount: "/srv/data:/data", blocked: true},
		{name: "private", mount: "/srv/data:/data:Z", blocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := fedoraComposeConfig(t, test.mount, true)
			host := fedoraHost()
			host.SELinux.Mode = "enforcing"
			host.Docker = facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}
			result, err := planner.New(Compose{}).Build(host, cfg)
			if err != nil || len(result.Changes) == 0 {
				t.Fatalf("Fedora SELinux plan = %#v, %v", result, err)
			}
			if (result.Changes[0].Blocked != "") != test.blocked {
				t.Fatalf("Fedora SELinux blocked=%t, want %t: %#v", result.Changes[0].Blocked != "", test.blocked, result.Changes)
			}
		})
	}
}

func TestFedoraSELinuxNamedVolumeDoesNotBlock(t *testing.T) {
	cfg := fedoraComposeConfig(t, "data:/data", false)
	host := fedoraHost()
	host.SELinux.Mode = "enforcing"
	host.Docker = facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}
	result, err := planner.New(Compose{}).Build(host, cfg)
	if err != nil || len(result.Changes) == 0 || result.Changes[0].Blocked != "" {
		t.Fatalf("named volume unexpectedly blocked: %#v, %v", result, err)
	}
}

func TestEnterpriseLinuxSELinuxUsesTheSameSharedBindRule(t *testing.T) {
	for _, test := range []struct {
		name, mount string
		blocked     bool
	}{
		{name: "named volume", mount: "data:/data", blocked: false},
		{name: "shared", mount: "/srv/data:/data:rw,z", blocked: false},
		{name: "plain", mount: "/srv/data:/data", blocked: true},
		{name: "private", mount: "/srv/data:/data:Z", blocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := !strings.HasPrefix(test.mount, "data:")
			cfg := fedoraComposeConfig(t, test.mount, path)
			host := enterpriseLinuxHost("rocky", "9.8")
			host.SELinux.Mode = "enforcing"
			host.Docker = facts.Docker{Installed: true, PackageSetComplete: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}
			result, err := planner.New(Compose{}).Build(host, cfg)
			if err != nil || len(result.Changes) == 0 || (result.Changes[0].Blocked != "") != test.blocked {
				t.Fatalf("EL SELinux plan = %#v, %v", result, err)
			}
		})
	}
}

func TestEnterpriseLinuxPlansAreDeterministic(t *testing.T) {
	for _, host := range []facts.HostFacts{
		enterpriseLinuxHost("rocky", "9.8"),
		enterpriseLinuxHost("almalinux", "10.2"),
		enterpriseLinuxHost("centos", "9"),
	} {
		planner := planner.New(Default()...)
		first, err := planner.Build(host, config.Defaults())
		if err != nil {
			t.Fatal(err)
		}
		second, err := planner.Build(host, config.Defaults())
		if err != nil || first.Fingerprint != second.Fingerprint || !reflect.DeepEqual(first.Changes, second.Changes) || !reflect.DeepEqual(first.Warnings, second.Warnings) {
			t.Fatalf("Enterprise Linux plan is not deterministic: %#v %#v %v", first, second, err)
		}
	}
}

func TestFedoraNonEnforcingSELinuxLeavesExistingBindBehaviorUnchanged(t *testing.T) {
	for _, mode := range []string{"permissive", "disabled", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			cfg := fedoraComposeConfig(t, "/srv/data:/data", true)
			host := fedoraHost()
			host.SELinux.Mode = mode
			host.Docker = facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}
			result, err := planner.New(Compose{}).Build(host, cfg)
			if err != nil || len(result.Changes) == 0 || result.Changes[0].Blocked != "" {
				t.Fatalf("SELinux %s unexpectedly blocked existing bind behavior: %#v, %v", mode, result, err)
			}
		})
	}
}

func TestUnsafeFedoraSELinuxBindCannotReachMutation(t *testing.T) {
	cfg := fedoraComposeConfig(t, "/srv/data:/data", true)
	host := fedoraHost()
	host.SELinux.Mode = "enforcing"
	host.Docker = facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposeAvailable: true}
	result, err := planner.New(Compose{}).Build(host, cfg)
	if err != nil || len(result.Changes) == 0 || result.Changes[0].Blocked == "" {
		t.Fatalf("unsafe Fedora bind did not produce a blocked plan: %#v, %v", result, err)
	}
	tr := &serviceRecordingTransport{}
	if _, err := apply.Execute(t.Context(), result, tr, cfg, nil, nil); err == nil || tr.calls != 0 {
		t.Fatalf("unsafe Fedora bind reached mutation: calls=%d err=%v", tr.calls, err)
	}
}

func fedoraComposeConfig(t *testing.T, mount string, path bool) config.Config {
	t.Helper()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "services", "hello"), 0o755); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  hello:\n    image: alpine:3.21\n    volumes:\n      - " + mount + "\n"
	data := "[[services.hello.data]]\nname = 'data'\ntype = 'volume'\nvolume = 'data'\n"
	if path {
		data = "[[services.hello.data]]\nname = 'data'\ntype = 'path'\npath = '/srv/data'\n"
	} else {
		compose += "volumes:\n  data: {}\n"
	}
	if err := os.WriteFile(filepath.Join(root, "services", "hello", "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	contents := "version = 1\n[services.hello]\ntype = 'compose'\nsource = 'services/hello'\n" + data
	if err := os.WriteFile(filepath.Join(root, "bebop.toml"), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
