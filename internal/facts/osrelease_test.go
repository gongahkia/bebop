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
		{"fedora.os-release", "fedora", "unsupported", "Fedora Linux", false},
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
