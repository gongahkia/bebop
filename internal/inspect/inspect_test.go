package inspect

import (
	"context"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestInspectUnconfiguredStorageUsesStructuredLSBLK(t *testing.T) {
	tr := storageTransport{output: `{"blockdevices":[
  {"name":"sdb","type":"disk","size":2000,"tran":"usb","mountpoints":[null]},
  {"name":"sda","type":"disk","size":1000,"children":[{"name":"sda1","type":"part","mountpoints":["/"]}]},
  {"name":"nvme0n1","type":"disk","size":3000,"mountpoints":[null]}
]}`}
	devices := inspectUnconfiguredStorage(context.Background(), tr)
	if len(devices) != 2 || devices[0].Name != "nvme0n1" || devices[1].Name != "sdb" || devices[1].Transport != "usb" {
		t.Fatalf("unexpected storage discovery: %#v", devices)
	}
}

func TestInspectStorageNormalizesDevicesMountsAndFallback(t *testing.T) {
	tr := scriptedStorageTransport{lsblk: `{"blockdevices":[{"name":"nvme0n1","path":"/dev/nvme0n1","type":"disk","size":1000,"tran":"nvme","children":[{"name":"nvme0n1p1","path":"/dev/nvme0n1p1","type":"part","size":900,"fstype":"ext4","label":"fast","uuid":"11111111-2222-3333-4444-555555555555","mountpoints":["/mnt/fast"]}]},{"name":"sdb","path":"/dev/sdb","type":"disk","size":2000,"rm":true,"tran":"usb","mountpoints":[null]}]}`, findmnt: `{"filesystems":[{"target":"/","source":"/dev/root","fstype":"ext4","options":"rw","size":500,"avail":200},{"target":"/mnt/fast","source":"/dev/nvme0n1p1","fstype":"ext4","options":"rw,noatime","size":900,"avail":600}]}`}
	storage := inspectStorage(context.Background(), tr)
	if !storage.Available || len(storage.Devices) != 3 || len(storage.Mounts) != 2 {
		t.Fatalf("unexpected normalized storage: %#v", storage)
	}
	if storage.Mounts[1].UUID != "11111111-2222-3333-4444-555555555555" || storage.Mounts[1].AvailableBytes != 600 || strings.Join(storage.Mounts[1].Options, ",") != "noatime,rw" {
		t.Fatalf("mount identity/capacity was not joined: %#v", storage.Mounts[1])
	}
	tr.findmnt = ""
	fallback := inspectStorage(context.Background(), tr)
	if !fallback.Available || len(fallback.Mounts) != 1 || fallback.Mounts[0].Target != "/mnt/fast" || fallback.Mounts[0].UUID == "" {
		t.Fatalf("lsblk fallback was not safe/useful: %#v", fallback)
	}
	tr.lsblk, tr.findmnt = "not-json", `{"filesystems":[{"target":"/mnt/fast","source":"/dev/nvme0n1p1","fstype":"ext4","options":"rw","size":900,"avail":600}]}`
	findmntOnly := inspectStorage(context.Background(), tr)
	if !findmntOnly.Available || len(findmntOnly.Devices) != 0 || len(findmntOnly.Mounts) != 1 || findmntOnly.Mounts[0].UUID != "" || findmntOnly.Mounts[0].AvailableBytes != 600 {
		t.Fatalf("findmnt-only fallback was not safely normalized: %#v", findmntOnly)
	}
}

func TestPackageToolProbeSelectsSupportedOSFamily(t *testing.T) {
	tr := packageProbeTransport{}
	manager, database := inspectPackageTools(context.Background(), tr, facts.OS{ID: "fedora", Family: "fedora", VersionID: "43", Supported: true})
	if manager != "dnf5" || database != "rpm" {
		t.Fatalf("Fedora package facts = %q/%q", manager, database)
	}
	tr.missingDNFOrRPM = true
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "fedora", Family: "fedora", VersionID: "43", Supported: true})
	if manager != "unknown" || database != "" {
		t.Fatalf("Fedora without dnf5/rpm was accepted as %q/%q", manager, database)
	}
	tr.missingDNFOrRPM = false
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "opensuse-leap", Family: "opensuse", VersionID: "16.0", Supported: true})
	if manager != "zypper" || database != "rpm" {
		t.Fatalf("openSUSE package facts = %q/%q", manager, database)
	}
	tr.missingDNFOrRPM = true
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "opensuse-tumbleweed", Family: "opensuse", VersionID: "20260122", Supported: true})
	if manager != "unknown" || database != "" {
		t.Fatalf("openSUSE without zypper/rpm was accepted as %q/%q", manager, database)
	}
	tr.missingDNFOrRPM = false
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "rocky", Family: "enterprise-linux", VersionID: "9.8", Supported: true})
	if manager != "dnf" || database != "rpm" {
		t.Fatalf("Enterprise Linux package facts = %q/%q", manager, database)
	}
	tr.missingDNFOrRPM = true
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "rocky", Family: "enterprise-linux", VersionID: "9.8", Supported: true})
	if manager != "unknown" || database != "" {
		t.Fatalf("Enterprise Linux without dnf/rpm was accepted as %q/%q", manager, database)
	}
	tr.missingDNFOrRPM = false
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "debian", Family: "debian", VersionID: "12", Supported: true})
	if manager != "apt" || database != "dpkg" {
		t.Fatalf("Debian package facts = %q/%q", manager, database)
	}
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "arch", Family: "arch", BuildID: "rolling", Supported: true})
	if manager != "pacman" || database != "" {
		t.Fatalf("Arch package facts = %q/%q", manager, database)
	}
	tr.missingPacman = true
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "arch", Family: "arch", BuildID: "rolling", Supported: true})
	if manager != "unknown" || database != "" {
		t.Fatalf("Arch without pacman was accepted as %q/%q", manager, database)
	}
	tr.missingPacman = false
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "alpine", Family: "alpine", VersionID: "3.24.2", Supported: true})
	if manager != "apk" || database != "" {
		t.Fatalf("Alpine package facts = %q/%q", manager, database)
	}
	tr.missingAPK = true
	manager, database = inspectPackageTools(context.Background(), tr, facts.OS{ID: "alpine", Family: "alpine", VersionID: "3.24.2", Supported: true})
	if manager != "unknown" || database != "" {
		t.Fatalf("Alpine without apk was accepted as %q/%q", manager, database)
	}
	if mode := inspectSELinux(context.Background(), tr).Mode; mode != "enforcing" {
		t.Fatalf("SELinux state was not normalized: %q", mode)
	}
}

func TestOpenSUSEPackageAvailabilityRequiresOfficialEnabledGPGCheckedRepository(t *testing.T) {
	repositories := `<?xml version="1.0"?><stream><repo-list><repo alias="openSUSE:repo-oss" name="repo-oss" enabled="1" gpgcheck="1" repo_gpgcheck="1" pkg_gpgcheck="1"><url>http://cdn.opensuse.org/distribution/leap/16.0/repo/oss/x86_64</url></repo></repo-list></stream>`
	packages := `<?xml version="1.0"?><stream><search-result><solvable-list><solvable name="docker" kind="package" repository="repo-oss"/><solvable name="docker-compose" kind="package" repository="repo-oss"/></solvable-list></search-result></stream>`
	if !openSUSEPackagesAvailable(repositories, packages, "docker", "docker-compose") {
		t.Fatal("official openSUSE package source was rejected")
	}
	if openSUSEPackagesAvailable(strings.ReplaceAll(repositories, "cdn.opensuse.org", "home.example.invalid"), packages, "docker", "docker-compose") {
		t.Fatal("third-party package source was accepted")
	}
	if openSUSEPackagesAvailable(strings.ReplaceAll(repositories, "pkg_gpgcheck=\"1\"", "pkg_gpgcheck=\"0\""), packages, "docker", "docker-compose") {
		t.Fatal("repository without package GPG checking was accepted")
	}
}

func TestMutationSafetyBlocksReadonlyAndTransactionalTargets(t *testing.T) {
	if blocked, _ := inspectMutationSafety(context.Background(), packageProbeTransport{}, facts.Filesystem{ReadOnly: true}); !blocked {
		t.Fatal("read-only root was not blocked")
	}
}

func TestAlpineRootModeFailsClosedForEphemeralInstallations(t *testing.T) {
	tr := packageProbeTransport{}
	for _, test := range []struct {
		root facts.Filesystem
		want string
	}{{facts.Filesystem{Type: "ext4"}, "persistent"}, {facts.Filesystem{Type: "tmpfs"}, "diskless"}, {facts.Filesystem{Type: "overlay"}, "ephemeral-overlay"}, {facts.Filesystem{Type: "ext4", ReadOnly: true}, "read-only"}} {
		if got := inspectAlpineRootMode(context.Background(), tr, test.root); got != test.want {
			t.Fatalf("Alpine root %#v mode = %q, want %q", test.root, got, test.want)
		}
	}
	if got := inspectAlpineRootMode(context.Background(), alpineLBUTransport{}, facts.Filesystem{Type: "ext4"}); got != "diskless-or-data" {
		t.Fatalf("Alpine lbu-managed root mode = %q, want diskless-or-data", got)
	}
}

type alpineLBUTransport struct{}

func (alpineLBUTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	if strings.Contains(request.Script, "/etc/lbu/lbu.conf") {
		return transport.Result{Stdout: "lbu-managed"}, nil
	}
	return transport.Result{}, nil
}
func (alpineLBUTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (alpineLBUTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (alpineLBUTransport) Description() string                              { return "alpine-lbu" }

type storageTransport struct{ output string }

func (s storageTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	return transport.Result{Stdout: s.output}, nil
}
func (storageTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (storageTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (storageTransport) Description() string                              { return "storage-fake" }

type scriptedStorageTransport struct{ lsblk, findmnt string }

func (s scriptedStorageTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	if strings.Contains(request.Script, "findmnt --json") {
		return transport.Result{Stdout: s.findmnt}, nil
	}
	return transport.Result{Stdout: s.lsblk}, nil
}
func (scriptedStorageTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (scriptedStorageTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (scriptedStorageTransport) Description() string                              { return "scripted-storage-fake" }

type packageProbeTransport struct {
	missingDNFOrRPM bool
	missingPacman   bool
	missingAPK      bool
}

func (tr packageProbeTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	switch {
	case strings.Contains(request.Script, "command -v dnf5"):
		if tr.missingDNFOrRPM {
			return transport.Result{}, nil
		}
		return transport.Result{Stdout: "dnf5 rpm"}, nil
	case strings.Contains(request.Script, "command -v dnf"):
		if tr.missingDNFOrRPM {
			return transport.Result{}, nil
		}
		return transport.Result{Stdout: "dnf rpm"}, nil
	case strings.Contains(request.Script, "command -v zypper"):
		if tr.missingDNFOrRPM {
			return transport.Result{}, nil
		}
		return transport.Result{Stdout: "zypper rpm"}, nil
	case strings.Contains(request.Script, "command -v apt-get"):
		return transport.Result{Stdout: "apt dpkg"}, nil
	case strings.Contains(request.Script, "command -v pacman"):
		if tr.missingPacman {
			return transport.Result{}, nil
		}
		return transport.Result{Stdout: "pacman"}, nil
	case strings.Contains(request.Script, "command -v apk"):
		if tr.missingAPK {
			return transport.Result{}, nil
		}
		return transport.Result{Stdout: "apk"}, nil
	case strings.Contains(request.Script, "getenforce"):
		return transport.Result{Stdout: "Enforcing"}, nil
	default:
		return transport.Result{}, nil
	}
}
func (packageProbeTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (packageProbeTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (packageProbeTransport) Description() string                              { return "package-probe" }
