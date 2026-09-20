package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestFromFactsSeparatesReadinessFailuresFromOperationalWarnings(t *testing.T) {
	host := facts.HostFacts{
		Target:            "ssh://pi@home",
		OS:                facts.OS{ID: "debian", Name: "Debian", VersionID: "12", Supported: true},
		Architecture:      "arm64",
		ArchitectureKnown: true,
		PackageManager:    "apt",
		PackageDatabase:   "dpkg",
		Systemd:           true,
		SudoAvailable:     true,
		DataRoot:          facts.Directory{Path: "/srv/bebop"},
	}
	result := FromFacts(target.Target{Kind: target.SSH, User: "pi", Host: "home"}, host)
	if !result.Ready || !result.Reachable || !result.Authenticated {
		t.Fatalf("supported host should be ready: %#v", result)
	}
	if len(result.Checks) == 0 || result.Checks[len(result.Checks)-1].Status != Warn {
		t.Fatalf("expected non-blocking operational warnings: %#v", result.Checks)
	}
	host.PackageManager = "unknown"
	blocked := FromFacts(target.Target{Kind: target.Local}, host)
	if blocked.Ready || blocked.FailureError() == nil {
		t.Fatalf("missing apt should block readiness: %#v", blocked)
	}
}

func TestFromFactsReportsFedoraDNF5RequirementsAccurately(t *testing.T) {
	host := facts.HostFacts{OS: facts.OS{ID: "fedora", Family: "fedora", VersionID: "44", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf5", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
	result := FromFacts(target.Target{Kind: target.Local}, host)
	if !result.Ready {
		t.Fatalf("Fedora 44 dnf5/rpm host was not ready: %#v", result)
	}
	found := false
	for _, check := range result.Checks {
		if check.Code == "package_manager.dnf5" && check.Status == Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("Fedora package-manager check did not identify dnf5/rpm: %#v", result.Checks)
	}
	host.PackageManager = "unknown"
	if FromFacts(target.Target{Kind: target.Local}, host).Ready {
		t.Fatal("Fedora without dnf5/rpm was ready")
	}
}

func TestFromFactsReportsEnterpriseLinuxDNFRequirementsAccurately(t *testing.T) {
	host := facts.HostFacts{OS: facts.OS{ID: "rocky", Name: "Rocky Linux", Family: "enterprise-linux", VersionID: "9.8", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "dnf", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
	result := FromFacts(target.Target{Kind: target.Local}, host)
	if !result.Ready {
		t.Fatalf("Enterprise Linux dnf/rpm host was not ready: %#v", result)
	}
	found := false
	for _, check := range result.Checks {
		if check.Code == "package_manager.dnf" && check.Status == Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("Enterprise Linux package-manager check did not identify dnf/rpm: %#v", result.Checks)
	}
	host.PackageManager = "dnf5"
	if FromFacts(target.Target{Kind: target.Local}, host).Ready {
		t.Fatal("Enterprise Linux without dnf/rpm was ready")
	}
}

func TestFromFactsReportsOpenSUSEZypperRequirementsAndMutableHostBoundary(t *testing.T) {
	host := facts.HostFacts{OS: facts.OS{ID: "opensuse-leap", Name: "openSUSE Leap", Family: "opensuse", VersionID: "16.0", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "zypper", PackageDatabase: "rpm", Systemd: true, SudoAvailable: true}
	result := FromFacts(target.Target{Kind: target.Local}, host)
	if !result.Ready {
		t.Fatalf("Leap zypper/rpm host was not ready: %#v", result)
	}
	found := false
	for _, check := range result.Checks {
		if check.Code == "package_manager.zypper" && check.Status == Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("openSUSE package-manager check did not identify zypper/rpm: %#v", result.Checks)
	}
	host.MutationBlocked, host.MutationBlockReason = true, "root filesystem is read-only"
	result = FromFacts(target.Target{Kind: target.Local}, host)
	if result.Ready || result.FailureError() == nil {
		t.Fatalf("immutable target was reported ready: %#v", result)
	}
}

func TestFromFactsReportsArchPacmanAndArchitectureRequirementsAccurately(t *testing.T) {
	host := facts.HostFacts{OS: facts.OS{ID: "arch", Name: "Arch Linux", Family: "arch", BuildID: "rolling", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "pacman", Systemd: true, SudoAvailable: true}
	result := FromFacts(target.Target{Kind: target.Local}, host)
	if !result.Ready {
		t.Fatalf("Arch pacman host was not ready: %#v", result)
	}
	found := false
	for _, check := range result.Checks {
		if check.Code == "package_manager.pacman" && check.Status == Pass && check.Message == "pacman package tool available" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Arch package-manager check did not identify pacman: %#v", result.Checks)
	}
	host.Architecture = "arm64"
	if FromFacts(target.Target{Kind: target.Local}, host).Ready {
		t.Fatal("Arch ARM was reported ready")
	}
}

func TestFromFactsReportsAlpineOpenRCAPKAndLockToolsAccurately(t *testing.T) {
	host := facts.HostFacts{OS: facts.OS{ID: "alpine", Name: "Alpine Linux", Family: "alpine", VersionID: "3.24.2", Supported: true}, Architecture: "arm64", ArchitectureKnown: true, PackageManager: "apk", InitSystem: facts.InitSystemOpenRC, SudoAvailable: true, PrivilegeMode: "doas", RequiredTools: facts.RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, RootMode: "persistent"}
	result := FromFacts(target.Target{Kind: target.Local}, host)
	if !result.Ready || result.InitSystem != facts.InitSystemOpenRC {
		t.Fatalf("Alpine OpenRC/APK host was not ready: %#v", result)
	}
	host.RequiredTools.Flock = false
	if FromFacts(target.Target{Kind: target.Local}, host).Ready {
		t.Fatal("Alpine without flock was reported ready for mutation")
	}
}

func TestDoctorMatrixRepresentativesAreReadyWithTheirReviewedBackends(t *testing.T) {
	tests := []struct {
		name string
		host facts.HostFacts
	}{
		{"debian", doctorHost(facts.OS{ID: "debian", VersionID: "12", Family: "debian", Supported: true}, "amd64", "", "apt", "dpkg", facts.InitSystemSystemd)},
		{"fedora", doctorHost(facts.OS{ID: "fedora", VersionID: "44", Family: "fedora", Supported: true}, "amd64", "", "dnf5", "rpm", facts.InitSystemSystemd)},
		{"opensuse", doctorHost(facts.OS{ID: "opensuse-leap", VersionID: "16.0", Family: "opensuse", Supported: true}, "amd64", "", "zypper", "rpm", facts.InitSystemSystemd)},
		{"arch", doctorHost(facts.OS{ID: "arch", BuildID: "rolling", Family: "arch", Supported: true}, "amd64", "", "pacman", "", facts.InitSystemSystemd)},
		{"alpine", doctorHost(facts.OS{ID: "alpine", VersionID: "3.24.2", Family: "alpine", Supported: true}, "arm64", "", "apk", "", facts.InitSystemOpenRC)},
		{"void", doctorHost(facts.OS{ID: "void", Family: "void", Supported: true}, "arm64", "musl", "xbps", "", facts.InitSystemRunit)},
		{"devuan", doctorHost(facts.OS{ID: "devuan", VersionID: "6", VersionCodename: "excalibur", Family: "devuan", Supported: true}, "arm64", "", "apt", "dpkg", facts.InitSystemSysV)},
		{"artix", doctorHost(facts.OS{ID: "artix", BuildID: "rolling", Family: "artix", Supported: true}, "amd64", "", "pacman", "", facts.InitSystemDinit)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := FromFacts(target.Target{Kind: target.Local}, test.host)
			if !result.Ready || result.Platform == "" || result.PackageManager != test.host.PackageManager || result.InitSystem != test.host.InitSystem {
				t.Fatalf("doctor did not render reviewed platform facts: %#v", result)
			}
		})
	}
}

func TestDoctorReportsActionablePlatformAndCapabilityBlockers(t *testing.T) {
	fedora := doctorHost(facts.OS{ID: "fedora", VersionID: "45", Family: "fedora", Supported: false}, "amd64", "", "dnf5", "rpm", facts.InitSystemSystemd)
	result := FromFacts(target.Target{Kind: target.Local}, fedora)
	if result.Ready || !hasCheck(result.Checks, "os.unsupported", Fail) || !hasCheck(result.Checks, "package_manager.dnf5", Pass) || !hasCheck(result.Checks, "init.detected", Pass) {
		t.Fatalf("unsupported Fedora did not retain useful detected facts: %#v", result.Checks)
	}
	artix := doctorHost(facts.OS{ID: "artix", BuildID: "rolling", Family: "artix", Supported: true}, "amd64", "", "pacman", "", facts.InitSystemRunit)
	if result := FromFacts(target.Target{Kind: target.Local}, artix); result.Ready || !hasCheck(result.Checks, "init.unsupported", Fail) {
		t.Fatalf("Artix with wrong active init was ready: %#v", result.Checks)
	}
	alpine := doctorHost(facts.OS{ID: "alpine", VersionID: "3.24.2", Family: "alpine", Supported: true}, "amd64", "", "apk", "", facts.InitSystemOpenRC)
	alpine.RequiredTools.Flock = false
	if result := FromFacts(target.Target{Kind: target.Local}, alpine); result.Ready || !hasCheck(result.Checks, "target.tool.flock", Fail) {
		t.Fatalf("Alpine missing flock was ready: %#v", result.Checks)
	}

	devuan := doctorHost(facts.OS{ID: "devuan", VersionID: "6", VersionCodename: "excalibur", Family: "devuan", Supported: true}, "amd64", "", "apt", "dpkg", facts.InitSystemSysV)
	devuan.Tailscale.RepositoryState = "unmanaged"
	cfg := config.Defaults()
	cfg.Features.Docker, cfg.Features.AutomaticUpdates = false, false
	result = fromFacts(target.Target{Kind: target.Local}, devuan)
	appendConfiguredCapabilityChecks(&result, cfg, devuan)
	if !hasCheck(result.Checks, "tailscale.repository_policy", Fail) {
		t.Fatalf("Devuan repository blocker missing: %#v", result.Checks)
	}

	void := doctorHost(facts.OS{ID: "void", Family: "void", Supported: true}, "amd64", "glibc", "xbps", "", facts.InitSystemRunit)
	void.Docker.PackageHeld = true
	cfg.Features.Docker, cfg.Features.Tailscale = true, false
	result = fromFacts(target.Target{Kind: target.Local}, void)
	appendConfiguredCapabilityChecks(&result, cfg, void)
	if !hasCheck(result.Checks, "docker.package_policy", Fail) {
		t.Fatalf("Void package hold blocker missing: %#v", result.Checks)
	}

	arch := doctorHost(facts.OS{ID: "arch", BuildID: "rolling", Family: "arch", Supported: true}, "amd64", "", "pacman", "", facts.InitSystemSystemd)
	cfg.Features.Docker, cfg.Features.Tailscale, cfg.Features.AutomaticUpdates = false, false, true
	result = fromFacts(target.Target{Kind: target.Local}, arch)
	appendConfiguredCapabilityChecks(&result, cfg, arch)
	if !hasCheck(result.Checks, "automatic_updates.unsupported", Fail) {
		t.Fatalf("Arch automatic-update blocker missing: %#v", result.Checks)
	}
}

func doctorHost(os facts.OS, architecture, libc, manager, database string, init facts.InitSystem) facts.HostFacts {
	return facts.HostFacts{OS: os, Architecture: architecture, ArchitectureKnown: true, Libc: libc, PackageManager: manager, PackageDatabase: database, InitSystem: init, Systemd: init == facts.InitSystemSystemd, SudoAvailable: true, PrivilegeMode: "sudo", RequiredTools: facts.RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, RootMode: "persistent", DataRoot: facts.Directory{Path: "/srv/bebop"}}
}

func hasCheck(checks []Check, code string, status Status) bool {
	for _, check := range checks {
		if check.Code == code && check.Status == status {
			return true
		}
	}
	return false
}

func TestBackupChecksDescribeControllerRepositoryWithoutMutatingIt(t *testing.T) {
	root := t.TempDir()
	cfg := config.WithSourceDirectory(config.Defaults(), root)
	cfg.Services = []config.Service{{Name: "hello", Type: "compose", Source: "services/hello", Data: []config.DataResource{{Name: "state", Type: "volume", Volume: "data"}}}}
	result := Result{}
	appendBackupChecks(&result, cfg)
	if len(result.Checks) != 2 || result.Checks[1].Code != "backup.destination_absent" {
		t.Fatalf("missing backup destination should be a non-mutating warning: %#v", result.Checks)
	}
	if _, err := os.Stat(filepath.Join(root, cfg.Backup.Destination)); !os.IsNotExist(err) {
		t.Fatalf("doctor unexpectedly created backup repository: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, cfg.Backup.Destination), 0o700); err != nil {
		t.Fatal(err)
	}
	result = Result{}
	appendBackupChecks(&result, cfg)
	if result.Checks[len(result.Checks)-1].Code != "backup.destination_ready" {
		t.Fatalf("existing backup destination was not reported ready: %#v", result.Checks)
	}
}

func TestFailureClassificationProducesActionableResult(t *testing.T) {
	result := unavailable(Result{Target: "ssh://pi@home"}, transport.ClassifyFailure(errors.New("Host key verification failed")), "SSH host-key verification failed")
	if result.Ready || result.Failure != transport.FailureHostKey || result.FailureError() == nil {
		t.Fatalf("unexpected unavailable result: %#v", result)
	}
}
