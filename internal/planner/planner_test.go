package planner_test

import (
	"context"
	"testing"

	"github.com/bebop-home/bebop/internal/apply"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/module"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/transport"
)

func initialFacts() facts.HostFacts {
	return facts.HostFacts{Target: "ssh://pi@home", OS: facts.OS{ID: "raspbian", Name: "Raspberry Pi OS", VersionID: "12", VersionCodename: "bookworm", Family: "raspberry-pi-os", Supported: true}, Architecture: "arm64", ArchitectureKnown: true, PackageManager: "apt", PackageDatabase: "dpkg", InitSystem: "systemd", Systemd: true, EffectiveUser: "pi", SudoAvailable: true, SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, DropInSupported: true, AuthorizedKeysPresent: true}, DataRoot: facts.Directory{Path: config.DefaultDataRoot}}
}

func TestPlanIsCanonicalAndIdempotentAfterTransitions(t *testing.T) {
	p := planner.New(modules.Default()...)
	cfg := config.Defaults()
	host := initialFacts()
	first, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := first.CanonicalJSON()
	secondJSON, _ := second.CanonicalJSON()
	if string(firstJSON) != string(secondJSON) || first.Fingerprint != second.Fingerprint {
		t.Fatalf("plan was not deterministic\n%s\n%s", firstJSON, secondJSON)
	}
	if len(first.Changes) != 7 {
		t.Fatalf("expected seven changes, got %d: %#v", len(first.Changes), first.Changes)
	}
	for _, id := range []string{"base.data-root", "docker.engine", "tailscale.package"} {
		found := false
		for _, change := range first.Changes {
			if change.ID == id && len(change.Preconditions) == 1 {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected module-level precondition for %s: %#v", id, first.Changes)
		}
	}
	transition(&host, first)
	converged, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(converged.Changes) != 0 {
		t.Fatalf("expected no changes after transition: %#v", converged.Changes)
	}
}

func TestFedoraRequiresDNF5RPMAndExplicitlySupportedRelease(t *testing.T) {
	p := planner.New()
	host := facts.HostFacts{Target: "local", OS: facts.OS{ID: "fedora", Family: "fedora", VersionID: "43", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf5", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
	if _, err := p.Build(host, config.Defaults()); err != nil {
		t.Fatalf("Fedora 43 with dnf5/rpm was rejected: %v", err)
	}
	host.PackageManager = "apt"
	if _, err := p.Build(host, config.Defaults()); err == nil {
		t.Fatal("Fedora was accepted with apt instead of dnf5/rpm")
	}
	host.PackageManager, host.PackageDatabase = "dnf5", ""
	if _, err := p.Build(host, config.Defaults()); err == nil {
		t.Fatal("Fedora was accepted without rpm")
	}
	host.PackageDatabase, host.OS.VersionID = "rpm", "45"
	if _, err := p.Build(host, config.Defaults()); err == nil {
		t.Fatal("Fedora 45 was accepted")
	}
}

func TestEnterpriseLinuxRequiresDNFAndExplicitReviewedIdentity(t *testing.T) {
	p := planner.New()
	valid := []facts.OS{
		{ID: "rocky", Family: "enterprise-linux", VersionID: "9.8", Supported: true},
		{ID: "rocky", Family: "enterprise-linux", VersionID: "10.2", Supported: true},
		{ID: "almalinux", Family: "enterprise-linux", VersionID: "9.8", Supported: true},
		{ID: "almalinux", Family: "enterprise-linux", VersionID: "10.2", Supported: true},
		{ID: "centos", Name: "CentOS Stream", Family: "enterprise-linux", VersionID: "9", PlatformID: "platform:el9", Supported: true},
		{ID: "centos", Name: "CentOS Stream", Family: "enterprise-linux", VersionID: "10", PlatformID: "platform:el10", Supported: true},
	}
	for _, os := range valid {
		host := facts.HostFacts{Target: "local", OS: os, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
		if _, err := p.Build(host, config.Defaults()); err != nil {
			t.Fatalf("%s was rejected with dnf/rpm: %v", os.Display(), err)
		}
		host.PackageManager = "dnf5"
		if _, err := p.Build(host, config.Defaults()); err == nil {
			t.Fatalf("%s accepted dnf5 instead of dnf", os.Display())
		}
		host.PackageManager, host.PackageDatabase = "dnf", ""
		if _, err := p.Build(host, config.Defaults()); err == nil {
			t.Fatalf("%s accepted without rpm", os.Display())
		}
	}
	unsupported := facts.HostFacts{Target: "local", OS: facts.OS{ID: "rocky", Family: "enterprise-linux", VersionID: "9.9", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
	if _, err := p.Build(unsupported, config.Defaults()); err == nil {
		t.Fatal("future Rocky minor was accepted")
	}
}

func TestOpenSUSERequiresZypperRPMAndMutableRoot(t *testing.T) {
	p := planner.New()
	for _, os := range []facts.OS{{ID: "opensuse-leap", Family: "opensuse", VersionID: "16.0", Supported: true}, {ID: "opensuse-tumbleweed", Family: "opensuse", VersionID: "20260122", Supported: true}} {
		host := facts.HostFacts{Target: "local", OS: os, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "zypper", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
		if _, err := p.Build(host, config.Defaults()); err != nil {
			t.Fatalf("%s with zypper/rpm was rejected: %v", os.Display(), err)
		}
		host.PackageManager = "dnf"
		if _, err := p.Build(host, config.Defaults()); err == nil {
			t.Fatalf("%s accepted dnf instead of zypper/rpm", os.Display())
		}
	}
	blocked := facts.HostFacts{Target: "local", OS: facts.OS{ID: "opensuse-leap", Family: "opensuse", VersionID: "16.0", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "zypper", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true, MutationBlocked: true, MutationBlockReason: "root filesystem is read-only"}
	if _, err := p.Build(blocked, config.Defaults()); err == nil {
		t.Fatal("read-only target was accepted for mutation")
	}
}

func TestArchRequiresOfficialRollingX8664AndPacman(t *testing.T) {
	p := planner.New()
	host := facts.HostFacts{Target: "local", OS: facts.OS{ID: "arch", Family: "arch", BuildID: "rolling", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "pacman", Systemd: true, SudoAvailable: true}
	if _, err := p.Build(host, config.Defaults()); err != nil {
		t.Fatalf("official Arch x86_64 with pacman was rejected: %v", err)
	}
	host.PackageManager = "apt"
	if _, err := p.Build(host, config.Defaults()); err == nil {
		t.Fatal("Arch was accepted with apt instead of pacman")
	}
	host.PackageManager, host.Architecture = "pacman", "arm64"
	if _, err := p.Build(host, config.Defaults()); err == nil {
		t.Fatal("Arch ARM was accepted")
	}
	host.Architecture, host.OS.BuildID = "amd64", "not-rolling"
	if _, err := p.Build(host, config.Defaults()); err == nil {
		t.Fatal("Arch with a non-rolling build identity was accepted")
	}
}

func TestApplyUsesPlanAndSecondApplyDoesNothing(t *testing.T) {
	p := planner.New(modules.Default()...)
	cfg := config.Defaults()
	host := initialFacts()
	reviewed, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr := &recordingTransport{}
	result, err := apply.Execute(context.Background(), reviewed, tr, cfg, p.Modules(), func(context.Context) (plan.Plan, error) { transition(&host, reviewed); return p.Build(host, cfg) })
	if err != nil {
		t.Fatal(err)
	}
	expectedOperations := len(reviewed.Changes) + len(reviewed.Changes)
	for _, change := range reviewed.Changes {
		expectedOperations += len(change.Preconditions)
	}
	if len(result.Verified) != len(reviewed.Changes) || tr.mutations != expectedOperations {
		t.Fatalf("apply/verify mismatch: %#v mutations=%d", result, tr.mutations)
	}
	before := tr.mutations
	if _, err := apply.Execute(context.Background(), result.Final, tr, cfg, p.Modules(), func(context.Context) (plan.Plan, error) { return result.Final, nil }); err != nil {
		t.Fatal(err)
	}
	if tr.mutations != before {
		t.Fatalf("second apply made operations: %d -> %d", before, tr.mutations)
	}
}

func transition(host *facts.HostFacts, result plan.Plan) {
	for _, change := range result.Changes {
		switch change.ID {
		case "base.data-root", "base.data-root.permissions":
			host.DataRoot.Exists = true
			host.DataRoot.Mode = "750"
			host.DataRoot.UID, host.DataRoot.GID = 0, 0
		case "updates.unattended":
			host.AutomaticUpdates = facts.AutomaticUpdates{Installed: true, Enabled: true}
		case "docker.engine":
			host.Docker.Installed = true
		case "docker.service":
			host.Docker.ServiceEnabled, host.Docker.ServiceActive, host.Docker.Responsive = true, true, true
		case "tailscale.package":
			host.Tailscale.Installed = true
		case "tailscale.service":
			host.Tailscale.ServiceEnabled, host.Tailscale.ServiceActive = true, true
		case "ssh.hardening":
			host.SSH.BebopDropIn = modules.SSHDropIn
			host.SSH.HardeningEffective = true
		}
	}
}

type recordingTransport struct{ mutations int }

func (r *recordingTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	r.mutations++
	return transport.Result{}, nil
}
func (r *recordingTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (r *recordingTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (r *recordingTransport) Description() string                              { return "recording" }

var _ module.Module = modules.Base{}
