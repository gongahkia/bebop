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
