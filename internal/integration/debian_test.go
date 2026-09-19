//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDebianInspect runs only when explicitly requested through make
// test-integration. It compiles a static Linux controller binary and executes
// read-only inspect inside a disposable Debian container; it never calls apply.
func TestDebianInspect(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "bebop")
	build := exec.Command("go", "build", "-o", binary, "./cmd/bebop")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux controller: %v\n%s", err, output)
	}
	command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", "debian:12", "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run disposable Debian inspect: %v\n%s", err, output)
	}
	var result struct {
		OS struct {
			ID        string `json:"id"`
			Supported bool   `json:"supported"`
		} `json:"os"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode inspect JSON: %v\n%s", err, output)
	}
	if result.OS.ID != "debian" || !result.OS.Supported {
		t.Fatalf("unexpected Debian inspection: %#v", result.OS)
	}
}

// TestFedoraInspect is deliberately read-only: a normal Fedora container does
// not model systemd-host behavior, but it does exercise real os-release and
// dnf5/rpm capability inspection against the supported images.
func TestFedoraInspect(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "bebop")
	build := exec.Command("go", "build", "-o", binary, "./cmd/bebop")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux controller: %v\n%s", err, output)
	}
	for _, image := range []string{"fedora:43", "fedora:44"} {
		t.Run(image, func(t *testing.T) {
			command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", image, "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("run disposable %s inspect: %v\n%s", image, err, output)
			}
			var result struct {
				OS struct {
					ID        string `json:"id"`
					VersionID string `json:"version_id"`
					Supported bool   `json:"supported"`
				} `json:"os"`
				PackageManager  string `json:"package_manager"`
				PackageDatabase string `json:"package_database"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode inspect JSON: %v\n%s", err, output)
			}
			if result.OS.ID != "fedora" || !result.OS.Supported || (result.OS.VersionID != "43" && result.OS.VersionID != "44") || result.PackageManager != "dnf5" || result.PackageDatabase != "rpm" {
				t.Fatalf("unexpected Fedora inspection: %#v", result)
			}
		})
	}
}

// TestEnterpriseLinuxInspect is read-only for the same reason as the Fedora
// coverage above: these containers validate release identity and dnf/rpm
// probing, not systemd-host mutation behavior.
func TestEnterpriseLinuxInspect(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "bebop")
	build := exec.Command("go", "build", "-o", binary, "./cmd/bebop")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux controller: %v\n%s", err, output)
	}
	for _, test := range []struct {
		image, id, version string
	}{
		{"rockylinux:9.8", "rocky", "9.8"},
		{"rockylinux:10.2", "rocky", "10.2"},
		{"almalinux:9.8", "almalinux", "9.8"},
		{"almalinux:10.2", "almalinux", "10.2"},
		{"quay.io/centos/centos:stream9", "centos", "9"},
		{"quay.io/centos/centos:stream10", "centos", "10"},
	} {
		t.Run(test.image, func(t *testing.T) {
			command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", test.image, "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("run disposable %s inspect: %v\n%s", test.image, err, output)
			}
			var result struct {
				OS struct {
					ID        string `json:"id"`
					VersionID string `json:"version_id"`
					Supported bool   `json:"supported"`
				} `json:"os"`
				PackageManager  string `json:"package_manager"`
				PackageDatabase string `json:"package_database"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode inspect JSON: %v\n%s", err, output)
			}
			if result.OS.ID != test.id || result.OS.VersionID != test.version || !result.OS.Supported || result.PackageManager != "dnf" || result.PackageDatabase != "rpm" {
				t.Fatalf("unexpected Enterprise Linux inspection: %#v", result)
			}
		})
	}
}
