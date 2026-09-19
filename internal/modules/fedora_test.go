package modules

import (
	"os"
	"path/filepath"
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
	host := facts.HostFacts{OS: facts.OS{ID: "debian", Family: "debian", VersionID: "12", Supported: true}, PackageManager: "apt", Systemd: true, SudoAvailable: true}
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
