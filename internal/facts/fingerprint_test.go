package facts

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestConvergenceFingerprintExcludesVolatileFactsAndIncludesPlannedState(t *testing.T) {
	host := HostFacts{
		Hostname:          "pi",
		MachineID:         "machine-a",
		OS:                OS{ID: "debian", VersionID: "12", Supported: true},
		Architecture:      "arm64",
		ArchitectureKnown: true,
		PackageManager:    "apt",
		PackageDatabase:   "dpkg",
		Systemd:           true,
		SudoAvailable:     true,
		Docker:            Docker{Installed: false},
		DataRoot:          Directory{Path: "/srv/bebop"},
	}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.Kernel = "different"
	host.MemoryKiB = 42
	host.RootFilesystem.AvailableKiB = 1
	second, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("volatile facts changed convergence fingerprint: %s != %s", first, second)
	}
	host.Docker.Installed = true
	third, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if first == third {
		t.Fatal("relevant Docker state did not change convergence fingerprint")
	}
}

func TestIdentityPrefersMachineIDAndFallsBackConservatively(t *testing.T) {
	expected := Identity{MachineID: "a", Hostname: "pi", OSID: "debian", OSVersion: "12"}
	if expected.Matches(Identity{MachineID: "b", Hostname: "pi", OSID: "debian", OSVersion: "12"}) {
		t.Fatal("different machine ID unexpectedly matched")
	}
	fallback := Identity{Hostname: "pi", OSID: "debian", OSVersion: "12"}
	if !fallback.Matches(Identity{Hostname: "pi", OSID: "debian", OSVersion: "12"}) || fallback.Matches(Identity{Hostname: "pi", OSID: "ubuntu", OSVersion: "24.04"}) {
		t.Fatal("fallback identity matching is not conservative")
	}
}

func TestServiceSecretMarkerParticipatesOnlyInConvergenceFingerprint(t *testing.T) {
	host := HostFacts{Services: []Service{{Name: "hello", Project: "bebop-hello", DesiredState: "running", DeploymentPresent: true, DeploymentDigest: "source", Runtime: "running", Health: "healthy", SecretFingerprint: "BEBOP_TEST_SECRET_DO_NOT_LEAK"}}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(host)
	if err != nil || strings.Contains(string(encoded), "BEBOP_TEST_SECRET_DO_NOT_LEAK") {
		t.Fatalf("service secret marker leaked through inspect/status JSON: %v %s", err, encoded)
	}
	host.Services[0].SecretFingerprint = "rotated-marker"
	second, err := host.ConvergenceFingerprint()
	if err != nil || first == second {
		t.Fatalf("service secret marker did not affect internal stale-state fingerprint: %q %q %v", first, second, err)
	}
}

func TestStorageThresholdPolicyParticipatesWithoutFreeSpaceChurn(t *testing.T) {
	host := HostFacts{Storage: Storage{Available: true, Mounts: []StorageMount{{Target: "/mnt/bulk", UUID: "11111111", AvailableBytes: 100}}, Policy: []StoragePolicy{{Name: "bulk", State: "ready"}}}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.Storage.Mounts[0].AvailableBytes = 99
	second, err := host.ConvergenceFingerprint()
	if err != nil || first != second {
		t.Fatalf("minor free-space telemetry changed fingerprint: %v", err)
	}
	host.Storage.Policy[0].State = "free-space-low"
	third, err := host.ConvergenceFingerprint()
	if err != nil || first == third {
		t.Fatalf("threshold classification did not change fingerprint: %v", err)
	}
	host.Storage.Policy[0].State = "ready"
	host.Storage.Mounts[0].Source = "/dev/nvme0n1p1"
	fourth, err := host.ConvergenceFingerprint()
	if err != nil || first != fourth {
		t.Fatalf("device path churn changed placement fingerprint: %v", err)
	}
}

func TestSELinuxEnforcementParticipatesInConvergenceFingerprint(t *testing.T) {
	host := HostFacts{OS: OS{ID: "fedora", VersionID: "43", Family: "fedora", Supported: true}, PackageManager: "dnf5", PackageDatabase: "rpm", SELinux: SELinux{Mode: "permissive"}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.SELinux.Mode = "enforcing"
	second, err := host.ConvergenceFingerprint()
	if err != nil || first == second {
		t.Fatalf("SELinux enforcement change did not stale convergence state: %v", err)
	}
}

func TestEnterpriseLinuxRepositoryPolicyAndSELinuxParticipateDeterministically(t *testing.T) {
	host := HostFacts{OS: OS{ID: "rocky", Name: "Rocky Linux", VersionID: "9.8", Family: "enterprise-linux", Supported: true}, PackageManager: "dnf", PackageDatabase: "rpm", Docker: Docker{RepositoryState: "absent", RepositoryPolicy: "rhel-9"}, SELinux: SELinux{Mode: "permissive"}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	second, err := host.ConvergenceFingerprint()
	if err != nil || first != second {
		t.Fatalf("identical Enterprise Linux facts are not deterministic: %q %q %v", first, second, err)
	}
	host.Docker.RepositoryState = "unmanaged"
	third, err := host.ConvergenceFingerprint()
	if err != nil || first == third {
		t.Fatalf("Docker repository ownership did not affect convergence: %v", err)
	}
	host.Docker.RepositoryState = "absent"
	host.SELinux.Mode = "enforcing"
	fourth, err := host.ConvergenceFingerprint()
	if err != nil || first == fourth {
		t.Fatalf("Enterprise Linux SELinux enforcement did not affect convergence: %v", err)
	}
}

func TestTumbleweedSnapshotDateIsNotConvergenceIdentityButPlannedStateIs(t *testing.T) {
	host := HostFacts{MachineID: "tw-machine", OS: OS{ID: "opensuse-tumbleweed", Family: "opensuse", VersionID: "20260122", Supported: true}, PackageManager: "zypper", PackageDatabase: "rpm", Docker: Docker{PackageSetAvailable: true}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.OS.VersionID = "20260916"
	second, err := host.ConvergenceFingerprint()
	if err != nil || first != second {
		t.Fatalf("display-only Tumbleweed snapshot date changed convergence: %v", err)
	}
	if !host.Identity().Matches(Identity{MachineID: "tw-machine", OSID: "opensuse-tumbleweed", OSVersion: "20260122"}) {
		t.Fatal("machine identity unexpectedly depends on Tumbleweed snapshot date")
	}
	host.Docker.PackageSetAvailable = false
	third, err := host.ConvergenceFingerprint()
	if err != nil || third == second {
		t.Fatalf("planner-relevant Tumbleweed package state did not stale convergence: %v", err)
	}
}

func TestArchRollingVersionMetadataIsNotConvergenceIdentityButPackageStateIs(t *testing.T) {
	host := HostFacts{MachineID: "arch-machine", OS: OS{ID: "arch", Family: "arch", BuildID: "rolling", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "pacman", Docker: Docker{PackageSetAvailable: true}, Tailscale: Tailscale{PackageAvailable: true}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	// Arch has no reviewed fixed release. Accidental/display-only VERSION_ID
	// metadata must not turn a rolling host into a distinct saved-plan state.
	host.OS.VersionID = "2026.09.19"
	second, err := host.ConvergenceFingerprint()
	if err != nil || first != second {
		t.Fatalf("display-only Arch version metadata changed convergence: %v", err)
	}
	if !host.Identity().Matches(Identity{MachineID: "arch-machine", OSID: "arch", OSVersion: ""}) {
		t.Fatal("machine identity unexpectedly depends on Arch rolling metadata")
	}
	host.Docker.PackageSetAvailable = false
	third, err := host.ConvergenceFingerprint()
	if err != nil || third == second {
		t.Fatalf("planner-relevant Arch package state did not stale convergence: %v", err)
	}
}

func TestVoidRollingIdentityExcludesImageMetadataButIncludesLibcAndRunitState(t *testing.T) {
	host := HostFacts{MachineID: "void-machine", OS: OS{ID: "void", Family: "void", VersionID: "20260920", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, Libc: "glibc", PackageManager: "xbps", InitSystem: InitSystemRunit, RequiredTools: RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, Docker: Docker{PackageSetAvailable: true, RepositoryPolicy: "https://repo-default.voidlinux.org/current"}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.OS.VersionID = "20261001"
	second, err := host.ConvergenceFingerprint()
	if err != nil || first != second {
		t.Fatalf("display-only Void rolling metadata changed convergence: %v", err)
	}
	if !host.Identity().Matches(Identity{MachineID: "void-machine", OSID: "void", OSVersion: ""}) {
		t.Fatal("Void machine identity unexpectedly depends on rolling metadata")
	}
	host.Libc = "musl"
	third, err := host.ConvergenceFingerprint()
	if err != nil || third == second {
		t.Fatalf("Void libc did not stale convergence: %v", err)
	}
	host.Libc = "glibc"
	host.InitSystem = InitSystemSystemd
	fourth, err := host.ConvergenceFingerprint()
	if err != nil || fourth == second {
		t.Fatalf("Void init system did not stale convergence: %v", err)
	}
}

func TestArtixRollingIdentityExcludesImageMetadataButIncludesDinitState(t *testing.T) {
	host := HostFacts{MachineID: "artix-machine", OS: OS{ID: "artix", Family: "artix", BuildID: "rolling", VersionID: "20260920", Supported: true}, Architecture: "amd64", ArchitectureKnown: true, PackageManager: "pacman", InitSystem: InitSystemDinit, RequiredTools: RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, Docker: Docker{PackageSetAvailable: true, RepositoryPolicy: "artix-world"}}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.OS.VersionID = "20260921"
	second, err := host.ConvergenceFingerprint()
	if err != nil || first != second {
		t.Fatalf("display-only Artix rolling metadata changed convergence: %v", err)
	}
	if host.Identity().OSVersion != "" {
		t.Fatal("Artix machine identity unexpectedly depends on rolling metadata")
	}
	host.InitSystem = InitSystemSystemd
	third, err := host.ConvergenceFingerprint()
	if err != nil || second == third {
		t.Fatalf("Artix dinit state did not participate in convergence: %v", err)
	}
}

func TestAlpineInitToolsAndPersistenceParticipateInConvergence(t *testing.T) {
	host := HostFacts{OS: OS{ID: "alpine", Family: "alpine", VersionID: "3.24.2", Supported: true}, Architecture: "arm64", ArchitectureKnown: true, PackageManager: "apk", InitSystem: InitSystemOpenRC, RequiredTools: RequiredTools{Flock: true, LSBLK: true, Findmnt: true}, RootMode: "persistent"}
	first, err := host.ConvergenceFingerprint()
	if err != nil {
		t.Fatal(err)
	}
	host.InitSystem = InitSystemSystemd
	second, err := host.ConvergenceFingerprint()
	if err != nil || first == second {
		t.Fatalf("Alpine init system did not stale convergence: %v", err)
	}
	host.InitSystem, host.RequiredTools.Flock = InitSystemOpenRC, false
	third, err := host.ConvergenceFingerprint()
	if err != nil || third == first {
		t.Fatalf("Alpine lock prerequisite did not stale convergence: %v", err)
	}
	host.RequiredTools.Flock, host.RootMode = true, "ephemeral-overlay"
	fourth, err := host.ConvergenceFingerprint()
	if err != nil || fourth == first {
		t.Fatalf("Alpine root mode did not stale convergence: %v", err)
	}
}
