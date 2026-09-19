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
			if !ensureIntegrationImage(t, test.image) {
				return
			}
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

// TestOpenSUSEInspect is read-only package/identity coverage. Containers do
// not provide the systemd host contract required for mutation tests.
func TestOpenSUSEInspect(t *testing.T) {
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
	for _, test := range []struct{ image, id string }{{"opensuse/leap:16.0", "opensuse-leap"}, {"opensuse/tumbleweed", "opensuse-tumbleweed"}} {
		t.Run(test.image, func(t *testing.T) {
			if !ensureIntegrationImage(t, test.image) {
				return
			}
			command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", test.image, "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("run disposable %s inspect: %v\n%s", test.image, err, output)
			}
			var result struct {
				OS struct {
					ID        string `json:"id"`
					Supported bool   `json:"supported"`
				} `json:"os"`
				PackageManager  string `json:"package_manager"`
				PackageDatabase string `json:"package_database"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode inspect JSON: %v\n%s", err, output)
			}
			if result.OS.ID != test.id || !result.OS.Supported || result.PackageManager != "zypper" || result.PackageDatabase != "rpm" {
				t.Fatalf("unexpected openSUSE inspection: %#v", result)
			}
		})
	}
}

// TestArchInspect is read-only identity and Pacman capability coverage. The
// Arch container deliberately does not stand in for a systemd host.
func TestArchInspect(t *testing.T) {
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
	const image = "archlinux:base"
	if !ensureIntegrationImage(t, image) {
		return
	}
	command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", image, "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run disposable Arch inspect: %v\n%s", err, output)
	}
	var result struct {
		OS struct {
			ID        string `json:"id"`
			BuildID   string `json:"build_id"`
			Supported bool   `json:"supported"`
		} `json:"os"`
		Architecture   string `json:"architecture"`
		PackageManager string `json:"package_manager"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode inspect JSON: %v\n%s", err, output)
	}
	if result.OS.ID != "arch" || result.OS.BuildID != "rolling" || !result.OS.Supported || result.Architecture != "amd64" || result.PackageManager != "pacman" {
		t.Fatalf("unexpected Arch inspection: %#v", result)
	}
}

// TestAlpineInspect is deliberately read-only. alpine:3.24 is an overlay-root
// container rather than a persistent OpenRC host, so this verifies identity,
// APK probing, and fail-closed installation-mode detection only.
func TestAlpineInspect(t *testing.T) {
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
	const image = "alpine:3.24"
	if !ensureIntegrationImage(t, image) {
		return
	}
	command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", image, "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run disposable Alpine inspect: %v\n%s", err, output)
	}
	var result struct {
		OS struct {
			ID        string `json:"id"`
			VersionID string `json:"version_id"`
			Supported bool   `json:"supported"`
		} `json:"os"`
		Architecture    string `json:"architecture"`
		PackageManager  string `json:"package_manager"`
		MutationBlocked bool   `json:"mutation_blocked"`
		RootMode        string `json:"root_mode"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode inspect JSON: %v\n%s", err, output)
	}
	if result.OS.ID != "alpine" || result.OS.VersionID != "3.24.2" || !result.OS.Supported || result.Architecture != "amd64" || result.PackageManager != "apk" || !result.MutationBlocked || result.RootMode != "ephemeral-overlay" {
		t.Fatalf("unexpected Alpine inspection: %#v", result)
	}
}

// TestAlpineAPKRepositorySyntax validates the apk-tools 3 parser contract for
// Bebop's owned tagged repository file and the packaged OpenRC service/config
// layout. It is not a host lifecycle test.
func TestAlpineAPKRepositorySyntax(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	const image = "alpine:3.24"
	if !ensureIntegrationImage(t, image) {
		return
	}
	script := `mkdir -p /etc/apk/repositories.d
printf '%s\n' '# Managed by Bebop. Manual edits may be replaced.' 'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main' 'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community' 'v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main' 'v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community' >/etc/apk/repositories.d/50-bebop.list
apk --interactive=no update --repositories-file /etc/apk/repositories.d/50-bebop.list >/dev/null
apk --interactive=no add --repositories-file /etc/apk/repositories.d/50-bebop.list docker@bebop-community docker-cli-compose@bebop-community docker-openrc@bebop-community tailscale@bebop-community tailscale-openrc@bebop-community apk-cron@bebop-main busybox-openrc openssh-server openssh-server-common-openrc >/dev/null
test -x /etc/init.d/docker
test -x /etc/init.d/cgroups
test -x /etc/init.d/tailscale
test -x /etc/init.d/crond
test -x /etc/init.d/sshd
grep -Fqx 'Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
grep -Fq reload /etc/init.d/docker
grep -Fq reload /etc/init.d/sshd
apk info -W /etc/periodic/daily/apk | grep -Fq apk-cron`
	if output, err := exec.Command("docker", "run", "--rm", image, "sh", "-ceu", script).CombinedOutput(); err != nil {
		t.Fatalf("validate Alpine APK repository syntax: %v\n%s", err, output)
	}
}

// TestVoidInspect and TestVoidXBPSPackageMetadata exercise the official Void
// image's rolling identity, native XBPS architecture, read-only repository
// metadata, and package-provided runit/SSH layout. The container's overlay
// root and non-runit PID 1 intentionally do not claim host lifecycle coverage.
func TestVoidInspect(t *testing.T) {
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
	const image = "voidlinux/voidlinux:latest"
	if !ensureIntegrationImage(t, image) {
		return
	}
	command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", image, "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run disposable Void inspect: %v\n%s", err, output)
	}
	var result struct {
		OS struct {
			ID        string `json:"id"`
			Supported bool   `json:"supported"`
		} `json:"os"`
		Architecture    string `json:"architecture"`
		Libc            string `json:"libc"`
		PackageManager  string `json:"package_manager"`
		MutationBlocked bool   `json:"mutation_blocked"`
		RootMode        string `json:"root_mode"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode inspect JSON: %v\n%s", err, output)
	}
	if result.OS.ID != "void" || !result.OS.Supported || result.Architecture != "amd64" || result.Libc != "glibc" || result.PackageManager != "xbps" || !result.MutationBlocked || result.RootMode != "ephemeral-overlay" {
		t.Fatalf("unexpected Void inspection: %#v", result)
	}
}

func TestVoidXBPSPackageMetadata(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	const image = "voidlinux/voidlinux:latest"
	if !ensureIntegrationImage(t, image) {
		return
	}
	script := `set -eu
test "$(xbps-uhelper arch)" = x86_64
query_metadata() {
  native_arch="$1"
  repository="$2"
  rootdir="/tmp/bebop-xbps-$native_arch"
  mkdir -p "$rootdir/usr/share/xbps.d" "$rootdir/etc/xbps.d"
  cp /usr/share/xbps.d/00-repository-main.conf /usr/share/xbps.d/void-virtualpkgs.conf /usr/share/xbps.d/xbps.conf "$rootdir/usr/share/xbps.d/"
  printf 'architecture=%s\n' "$native_arch" > "$rootdir/usr/share/xbps.d/xbps-arch.conf"
  for package in docker docker-compose tailscale; do
    xbps-query -r "$rootdir" --ignore-conf-repos --repository="$repository" -M -S "$package" >/dev/null
  done
}
query_metadata x86_64 https://repo-default.voidlinux.org/current
query_metadata x86_64-musl https://repo-default.voidlinux.org/current/musl
query_metadata aarch64 https://repo-default.voidlinux.org/current/aarch64
query_metadata aarch64-musl https://repo-default.voidlinux.org/current/aarch64
for package in docker docker-compose tailscale; do
  xbps-query --ignore-conf-repos --repository=https://repo-default.voidlinux.org/current -M -S "$package" >/dev/null
done
xbps-query --ignore-conf-repos --repository=https://repo-default.voidlinux.org/current -M -f moby | grep -Fqx /etc/sv/docker/run
xbps-query --ignore-conf-repos --repository=https://repo-default.voidlinux.org/current -M -f tailscale | grep -Fqx /etc/sv/tailscaled/run
xbps-query --ignore-conf-repos --repository=https://repo-default.voidlinux.org/current -M --cat=/etc/ssh/sshd_config openssh | grep -Fqx 'Include /etc/ssh/sshd_config.d/*.conf'
command -v flock >/dev/null
command -v lsblk >/dev/null
command -v findmnt >/dev/null`
	if output, err := exec.Command("docker", "run", "--rm", image, "sh", "-ceu", script).CombinedOutput(); err != nil {
		t.Fatalf("validate Void XBPS/package layout: %v\n%s", err, output)
	}
}

// ensureIntegrationImage keeps optional read-only coverage useful when a
// vendor retires a specifically reviewed image tag. A pull failure is an
// unavailable external test prerequisite, not evidence that Bebop accepts an
// unsupported OS; fixture and unit tests retain that release-policy coverage.
func ensureIntegrationImage(t *testing.T, image string) bool {
	t.Helper()
	if err := exec.Command("docker", "image", "inspect", image).Run(); err == nil {
		return true
	}
	if output, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
		t.Skipf("external integration image %s unavailable: %v\n%s", image, err, output)
		return false
	}
	return true
}
