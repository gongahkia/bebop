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
