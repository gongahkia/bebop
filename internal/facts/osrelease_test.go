package facts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseOSReleaseFixtures(t *testing.T) {
	tests := []struct {
		fixture, id, family, name string
		supported                 bool
	}{
		{"debian.os-release", "debian", "debian", "Debian GNU/Linux", true},
		{"ubuntu.os-release", "ubuntu", "ubuntu", "Ubuntu", true},
		{"raspberry-pi-os.os-release", "raspbian", "raspberry-pi-os", "Raspberry Pi OS", true},
		{"fedora.os-release", "fedora", "fedora", "Fedora Linux", true},
		{"fedora-44.os-release", "fedora", "fedora", "Fedora Linux", true},
		{"fedora-42.os-release", "fedora", "fedora", "Fedora Linux", false},
		{"fedora-45.os-release", "fedora", "fedora", "Fedora Linux", false},
		{"rocky-9.8.os-release", "rocky", "enterprise-linux", "Rocky Linux", true},
		{"rocky-10.2.os-release", "rocky", "enterprise-linux", "Rocky Linux", true},
		{"almalinux-9.8.os-release", "almalinux", "enterprise-linux", "AlmaLinux", true},
		{"almalinux-10.2.os-release", "almalinux", "enterprise-linux", "AlmaLinux", true},
		{"centos-stream-9.os-release", "centos", "enterprise-linux", "CentOS Stream", true},
		{"centos-stream-10.os-release", "centos", "enterprise-linux", "CentOS Stream", true},
		{"opensuse-leap-16.0.os-release", "opensuse-leap", "opensuse", "openSUSE Leap", true},
		{"opensuse-tumbleweed-20260122.os-release", "opensuse-tumbleweed", "opensuse", "openSUSE Tumbleweed", true},
		{"opensuse-tumbleweed-20260916.os-release", "opensuse-tumbleweed", "opensuse", "openSUSE Tumbleweed", true},
		{"arch.os-release", "arch", "arch", "Arch Linux", true},
		{"alpine-3.24.0.os-release", "alpine", "alpine", "Alpine Linux", true},
		{"alpine-3.24.2.os-release", "alpine", "alpine", "Alpine Linux", true},
		{"alpine-3.24.99.os-release", "alpine", "alpine", "Alpine Linux", true},
	}
	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join("testdata", test.fixture))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := ParseOSRelease(string(contents))
			if err != nil {
				t.Fatal(err)
			}
			if actual.ID != test.id || actual.Family != test.family || actual.Name != test.name || actual.Supported != test.supported {
				t.Fatalf("unexpected OS: %#v", actual)
			}
		})
	}
}

func TestAlpineIdentityArchitectureAndPackageToolsAreExplicitlyGated(t *testing.T) {
	for _, fixture := range []string{"alpine-3.23.9.os-release", "alpine-3.25.0.os-release", "alpine-edge.os-release", "alpine-rc.os-release", "generic-alpine-like.os-release"} {
		contents, err := os.ReadFile(filepath.Join("testdata", fixture))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseOSRelease(string(contents))
		if err != nil || parsed.Supported || parsed.IsSupported() {
			t.Fatalf("unsupported Alpine-like fixture was accepted: %#v, %v", parsed, err)
		}
	}
	alpine := OS{ID: "alpine", Family: "alpine", VersionID: "3.24.2", Supported: true}
	if !alpine.IsSupported() || !alpine.SupportsArchitecture("amd64") || !alpine.SupportsArchitecture("arm64") || alpine.SupportsArchitecture("riscv64") || alpine.RequiredInitSystem() != InitSystemOpenRC {
		t.Fatalf("Alpine identity/init/architecture gate was not strict: %#v", alpine)
	}
	manager, database, ok := RequiredPackageTools(alpine)
	if !ok || manager != "apk" || database != "" || !PackageToolsAvailable(alpine, "apk", "") || PackageToolsAvailable(alpine, "apt", "dpkg") || PackageToolsAvailable(alpine, "dnf", "rpm") || PackageToolsAvailable(alpine, "zypper", "rpm") || PackageToolsAvailable(alpine, "pacman", "") {
		t.Fatalf("Alpine package tools were not strictly normalized: %q/%q %t", manager, database, ok)
	}
}

func TestArchIdentityAndArchitectureAreExplicitlyGated(t *testing.T) {
	for _, fixture := range []string{"arch-build-invalid.os-release", "manjaro.os-release", "endeavouros.os-release", "cachyos.os-release", "generic-arch-like.os-release"} {
		t.Run(fixture, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := ParseOSRelease(string(contents))
			if err != nil || actual.Supported || actual.IsSupported() {
				t.Fatalf("unsupported Arch-like fixture was accepted: %#v, %v", actual, err)
			}
		})
	}
	for _, id := range []string{"garuda", "artix"} {
		actual, err := ParseOSRelease("ID=" + id + "\nID_LIKE=arch\nBUILD_ID=rolling\n")
		if err != nil || actual.Supported || actual.IsSupported() {
			t.Fatalf("Arch derivative %q was accepted: %#v, %v", id, actual, err)
		}
	}
	arch, err := ParseOSRelease("ID=arch\nBUILD_ID=rolling\n")
	if err != nil || !arch.IsSupported() || !arch.SupportsArchitecture("amd64") || arch.SupportsArchitecture("arm64") {
		t.Fatalf("Arch identity/architecture gate was not strict: %#v, %v", arch, err)
	}
}

func TestArchRequiresOnlyPacman(t *testing.T) {
	arch := OS{ID: "arch", Family: "arch", BuildID: "rolling", Supported: true}
	manager, database, ok := RequiredPackageTools(arch)
	if !ok || manager != "pacman" || database != "" || !PackageToolsAvailable(arch, "pacman", "") || PackageToolsAvailable(arch, "apt", "dpkg") || PackageToolsAvailable(arch, "dnf", "rpm") || PackageToolsAvailable(arch, "dnf5", "rpm") || PackageToolsAvailable(arch, "zypper", "rpm") {
		t.Fatalf("Arch package tools were not strictly normalized: %q/%q %t", manager, database, ok)
	}
}

func TestOpenSUSEVersionsAndDerivativesAreExplicitlyGated(t *testing.T) {
	for _, fixture := range []string{"opensuse-leap-15.6.os-release", "opensuse-leap-16.1.os-release", "opensuse-microos.os-release", "opensuse-slowroll.os-release", "generic-opensuse-like.os-release"} {
		t.Run(fixture, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := ParseOSRelease(string(contents))
			if err != nil || actual.Supported || actual.IsSupported() {
				t.Fatalf("unsupported openSUSE fixture was accepted: %#v, %v", actual, err)
			}
		})
	}
	for _, version := range []string{"15.6", "16.1", "17.0", ""} {
		actual, err := ParseOSRelease("ID=opensuse-leap\nVERSION_ID=" + version + "\n")
		if err != nil || actual.Supported || actual.IsSupported() {
			t.Fatalf("unreviewed Leap %q was accepted: %#v, %v", version, actual, err)
		}
	}
}

func TestOpenSUSERequiresZypperAndRPM(t *testing.T) {
	for _, os := range []OS{{ID: "opensuse-leap", Family: "opensuse", VersionID: "16.0", Supported: true}, {ID: "opensuse-tumbleweed", Family: "opensuse", VersionID: "20260122", Supported: true}} {
		manager, database, ok := RequiredPackageTools(os)
		if !ok || manager != "zypper" || database != "rpm" || !PackageToolsAvailable(os, "zypper", "rpm") || PackageToolsAvailable(os, "dnf", "rpm") || PackageToolsAvailable(os, "apt", "dpkg") {
			t.Fatalf("openSUSE package tools were not strictly normalized: %#v -> %q/%q %t", os, manager, database, ok)
		}
	}
}

func TestEnterpriseLinuxVersionsAndDerivativesAreExplicitlyGated(t *testing.T) {
	for _, fixture := range []string{
		"rocky-9.7.os-release", "rocky-9.9.os-release", "rocky-10.1.os-release", "rocky-10.3.os-release",
		"almalinux-9.7.os-release", "almalinux-9.9-beta.os-release", "almalinux-10.1.os-release", "almalinux-10.3-beta.os-release",
		"centos-linux-9.os-release", "centos-stream-malformed.os-release", "oracle-9.os-release", "rhel-9.os-release", "generic-rhel-like.os-release", "almalinux-kitten-10.os-release",
	} {
		t.Run(fixture, func(t *testing.T) {
			contents, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatal(err)
			}
			actual, err := ParseOSRelease(string(contents))
			if err != nil || actual.Supported || actual.IsSupported() {
				t.Fatalf("unsupported fixture was accepted: %#v, %v", actual, err)
			}
		})
	}
}

func TestEnterpriseLinuxRepositoryPoliciesAreExplicit(t *testing.T) {
	tests := []struct {
		os                OS
		docker, tailscale string
	}{
		{OS{ID: "rocky", Family: "enterprise-linux", VersionID: "9.8", Supported: true}, "rhel-9", "rhel-9"},
		{OS{ID: "rocky", Family: "enterprise-linux", VersionID: "10.2", Supported: true}, "rhel-10", "rhel-10"},
		{OS{ID: "almalinux", Family: "enterprise-linux", VersionID: "9.8", Supported: true}, "rhel-9", "rhel-9"},
		{OS{ID: "almalinux", Family: "enterprise-linux", VersionID: "10.2", Supported: true}, "rhel-10", "rhel-10"},
		{OS{ID: "centos", Name: "CentOS Stream", Family: "enterprise-linux", VersionID: "9", PlatformID: "platform:el9", Supported: true}, "centos-9", "centos-9"},
		{OS{ID: "centos", Name: "CentOS Stream", Family: "enterprise-linux", VersionID: "10", PlatformID: "platform:el10", Supported: true}, "centos-10", "centos-10"},
	}
	for _, test := range tests {
		family, major, ok := DockerCERepositoryPolicy(test.os)
		if !ok || family+"-"+major != test.docker {
			t.Fatalf("Docker policy for %#v = %s-%s, %t", test.os, family, major, ok)
		}
		family, major, ok = TailscaleRPMRepositoryPolicy(test.os)
		if !ok || family+"-"+major != test.tailscale {
			t.Fatalf("Tailscale policy for %#v = %s-%s, %t", test.os, family, major, ok)
		}
	}
}

func TestEnterpriseLinuxRequiresDNFAndRPM(t *testing.T) {
	os := OS{ID: "rocky", Family: "enterprise-linux", VersionID: "9.8", Supported: true}
	manager, database, ok := RequiredPackageTools(os)
	if !ok || manager != "dnf" || database != "rpm" || !PackageToolsAvailable(os, "dnf", "rpm") || PackageToolsAvailable(os, "dnf5", "rpm") || PackageToolsAvailable(os, "dnf", "") {
		t.Fatalf("Enterprise Linux package tools were not strictly normalized: %q/%q %t", manager, database, ok)
	}
}

func TestFedoraVersionsAreExplicitlyGated(t *testing.T) {
	for _, version := range []string{"42", "43", "44", "45", "rawhide", ""} {
		os, err := ParseOSRelease("ID=fedora\nVERSION_ID=" + version + "\n")
		if err != nil {
			t.Fatal(err)
		}
		want := version == "43" || version == "44"
		if os.Supported != want {
			t.Fatalf("Fedora %q supported=%t, want %t", version, os.Supported, want)
		}
	}
}

func TestUnrelatedDistributionRemainsUnsupported(t *testing.T) {
	os, err := ParseOSRelease("ID=rocky\nVERSION_ID=9.5\n")
	if err != nil || os.Supported || os.Family != "enterprise-linux" {
		t.Fatalf("unrelated distribution was accepted: %#v %v", os, err)
	}
}

func TestNormalizeSELinuxMode(t *testing.T) {
	for _, test := range []struct{ raw, want string }{{"Enforcing", "enforcing"}, {"permissive", "permissive"}, {"Disabled", "disabled"}, {"", "unavailable"}, {"unknown", "unavailable"}} {
		if got := NormalizeSELinuxMode(test.raw); got != test.want {
			t.Fatalf("NormalizeSELinuxMode(%q) = %q, want %q", test.raw, got, test.want)
		}
	}
}

func TestNormalizeArchitecture(t *testing.T) {
	for _, test := range []struct {
		raw, expected string
		known         bool
	}{{"x86_64", "amd64", true}, {"aarch64", "arm64", true}, {"riscv64", "riscv64", false}} {
		actual, known := NormalizeArchitecture(test.raw)
		if actual != test.expected || known != test.known {
			t.Fatalf("%q: got %q %t", test.raw, actual, known)
		}
	}
}
