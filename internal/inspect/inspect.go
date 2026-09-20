// Package inspect gathers normalized facts through a transport. It is strictly
// read-only: every request is a probe, never a package, service, or file change.
package inspect

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/services"
	storagepolicy "github.com/bebop-home/bebop/internal/storage"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

type Inspector struct{}

func (Inspector) Inspect(ctx context.Context, tr transport.Transport, target target.Target, cfg config.Config) (facts.HostFacts, error) {
	dataRoot := cfg.Storage.DataRoot
	contents, err := tr.ReadFile(ctx, "/etc/os-release")
	if err != nil {
		kernelName := firstLine(mustProbe(ctx, tr, "uname -s"))
		if kernelName != "" {
			return facts.HostFacts{}, errs.New(errs.UnsupportedOS, "target does not expose /etc/os-release; "+kernelName+" targets are not supported in Bebop M0", nil)
		}
		return facts.HostFacts{}, errs.New(errs.TargetUnreachable, "cannot read /etc/os-release from target", err)
	}
	osFacts, err := facts.ParseOSRelease(contents)
	if err != nil {
		return facts.HostFacts{}, fmt.Errorf("parse target os-release: %w", err)
	}
	f := facts.HostFacts{Target: target.String(), OS: osFacts, PackageManager: "unknown", DataRoot: facts.Directory{Path: dataRoot}, SELinux: facts.SELinux{Mode: "unavailable"}}
	f.Hostname = firstLine(mustProbe(ctx, tr, "hostname"))
	f.MachineID = firstLine(mustProbe(ctx, tr, "cat /etc/machine-id 2>/dev/null || true"))
	rawArchitecture := firstLine(mustProbe(ctx, tr, "uname -m"))
	f.Architecture, f.ArchitectureKnown = facts.NormalizeArchitecture(rawArchitecture)
	f.Kernel = firstLine(mustProbe(ctx, tr, "uname -r"))
	f.EffectiveUser = firstLine(mustProbe(ctx, tr, "id -un"))
	f.PrivilegeMode = inspectPrivilegeMode(ctx, tr)
	f.SudoAvailable = f.PrivilegeMode != "unavailable"
	f.InitSystem = inspectInitSystem(ctx, tr)
	f.Systemd = f.InitSystem == facts.InitSystemSystemd
	f.PackageManager, f.PackageDatabase = inspectPackageTools(ctx, tr, f.OS)
	if f.OS.Family == "void" && f.PackageManager == "xbps" {
		if architecture, libc, ok := facts.NormalizeVoidArchitecture(firstLine(mustProbe(ctx, tr, "xbps-uhelper arch"))); ok {
			f.Architecture, f.ArchitectureKnown, f.Libc = architecture, true, libc
		} else {
			f.ArchitectureKnown = false
		}
	}
	f.RequiredTools = inspectRequiredTools(ctx, tr, f.OS)
	f.SSH = inspectSSH(ctx, tr, f.InitSystem)
	f.SELinux = inspectSELinux(ctx, tr)
	f.Docker = inspectDocker(ctx, tr, f.InitSystem, f.PackageManager, f.OS)
	deployments, err := services.ResolveAll(cfg)
	if err != nil {
		return facts.HostFacts{}, err
	}
	f.Services = inspectServices(ctx, tr, dataRoot, deployments, f.Docker.Responsive)
	f.Tailscale = inspectTailscale(ctx, tr, f.InitSystem, f.PackageManager, f.OS)
	f.AutomaticUpdates = inspectUpdates(ctx, tr, f.InitSystem, f.PackageManager, f.OS)
	f.MaintenanceUpdateCheckAvailable = inspectMaintenanceUpdateCheck(ctx, tr, f.PackageManager)
	f.Firewall = inspectFirewall(ctx, tr)
	f.MemoryKiB = parseMemory(mustProbe(ctx, tr, "awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true"))
	f.RootFilesystem = inspectRootFilesystem(ctx, tr)
	f.MutationBlocked, f.MutationBlockReason = inspectMutationSafety(ctx, tr, f.RootFilesystem)
	f.RootMode = "persistent"
	platform, platformSupported := facts.PlatformPolicyFor(f.OS)
	if platformSupported && platform.RootPersistence == facts.RootPersistencePersistent && f.OS.ID == "alpine" {
		f.RootMode = inspectAlpineRootMode(ctx, tr, f.RootFilesystem)
		if f.RootMode != "persistent" {
			f.MutationBlocked, f.MutationBlockReason = true, "Alpine "+f.RootMode+" root cannot preserve Bebop mutations across reboot"
		}
	}
	if platformSupported && platform.RootPersistence == facts.RootPersistencePersistent && f.OS.ID != "alpine" {
		f.RootMode = inspectVoidRootMode(f.RootFilesystem)
		if f.RootMode != "persistent" {
			f.MutationBlocked, f.MutationBlockReason = true, f.OS.Display()+" "+f.RootMode+" root cannot preserve Bebop mutations across reboot"
		}
	}
	f.UnconfiguredStorage = inspectUnconfiguredStorage(ctx, tr)
	f.Storage = inspectStorage(ctx, tr)
	f.Storage.MountConfigs = inspectManagedMountConfigs(ctx, tr, cfg.Storage.Resources)
	for _, assessment := range storagepolicy.AssessAll(cfg.Storage, f.Storage) {
		f.Storage.Policy = append(f.Storage.Policy, facts.StoragePolicy{Name: assessment.Resource.Name, State: string(assessment.State)})
	}
	f.DataRoot = inspectDataRoot(ctx, tr, dataRoot)
	return f, nil
}

func inspectPrivilegeMode(ctx context.Context, tr transport.Transport) string {
	return firstLine(mustProbe(ctx, tr, `if test "$(id -u)" -eq 0; then
  printf root
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  printf sudo
elif command -v doas >/dev/null 2>&1 && doas -n true >/dev/null 2>&1; then
  printf doas
else
  printf unavailable
fi`))
}

func inspectInitSystem(ctx context.Context, tr transport.Transport) facts.InitSystem {
	switch firstLine(mustProbe(ctx, tr, `if command -v systemctl >/dev/null 2>&1 && test -d /run/systemd/system; then
  printf systemd
elif command -v rc-service >/dev/null 2>&1 && command -v rc-update >/dev/null 2>&1 && test -d /run/openrc; then
  printf openrc
elif command -v sv >/dev/null 2>&1 && command -v pgrep >/dev/null 2>&1 && test -d /etc/runit && test -L /var/service && test -d /var/service && test "$(readlink -f /var/service)" = /run/runit/runsvdir/current && pgrep -x runsvdir >/dev/null 2>&1; then
  printf runit
elif test "$(basename "$(readlink -f /proc/1/exe 2>/dev/null || true)")" = init && command -v service >/dev/null 2>&1 && command -v update-rc.d >/dev/null 2>&1 && dpkg-query -W -f='${db:Status-Status}' sysvinit-core 2>/dev/null | grep -qx installed; then
  printf sysvinit
elif test "$(basename "$(readlink -f /proc/1/exe 2>/dev/null || true)")" = dinit && command -v dinitctl >/dev/null 2>&1 && dinitctl -s status boot >/dev/null 2>&1; then
  printf dinit
else
  printf unknown
fi`)) {
	case string(facts.InitSystemSystemd), "yes":
		return facts.InitSystemSystemd
	case string(facts.InitSystemOpenRC):
		return facts.InitSystemOpenRC
	case string(facts.InitSystemRunit):
		return facts.InitSystemRunit
	case string(facts.InitSystemSysV):
		return facts.InitSystemSysV
	case string(facts.InitSystemDinit):
		return facts.InitSystemDinit
	default:
		return facts.InitSystemUnknown
	}
}

func inspectRequiredTools(ctx context.Context, tr transport.Transport, os facts.OS) facts.RequiredTools {
	if required, _ := facts.MutationToolPolicy(os); !required {
		return facts.RequiredTools{}
	}
	lines := probeLines(ctx, tr, `
if command -v flock >/dev/null 2>&1; then printf 'flock=yes\n'; else printf 'flock=no\n'; fi
if command -v lsblk >/dev/null 2>&1; then printf 'lsblk=yes\n'; else printf 'lsblk=no\n'; fi
if command -v findmnt >/dev/null 2>&1; then printf 'findmnt=yes\n'; else printf 'findmnt=no\n'; fi`)
	return facts.RequiredTools{Flock: lines["flock"] == "yes", LSBLK: lines["lsblk"] == "yes", Findmnt: lines["findmnt"] == "yes"}
}

func inspectMaintenanceUpdateCheck(ctx context.Context, tr transport.Transport, packageManager string) bool {
	if packageManager == "pacman" {
		return firstLine(mustProbe(ctx, tr, "if command -v checkupdates >/dev/null 2>&1; then printf yes; fi")) == "yes"
	}
	// Every other reviewed package-manager backend performs update awareness
	// with a tool already required by its package capability.
	return packageManager != "" && packageManager != "unknown"
}

func inspectPackageTools(ctx context.Context, tr transport.Transport, os facts.OS) (string, string) {
	manager, database, known := facts.RequiredPackageTools(os)
	if !known {
		return "unknown", ""
	}
	var script string
	switch manager {
	case "apt":
		script = "if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then printf 'apt dpkg'; fi"
	case "dnf5":
		script = "if command -v dnf5 >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then printf 'dnf5 rpm'; fi"
	case "dnf":
		script = "if command -v dnf >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then printf 'dnf rpm'; fi"
	case "zypper":
		script = "if command -v zypper >/dev/null 2>&1 && command -v rpm >/dev/null 2>&1; then printf 'zypper rpm'; fi"
	case "pacman":
		script = "if command -v pacman >/dev/null 2>&1; then printf pacman; fi"
	case "apk":
		script = "if command -v apk >/dev/null 2>&1; then printf apk; fi"
	case "xbps":
		script = "if command -v xbps-install >/dev/null 2>&1 && command -v xbps-query >/dev/null 2>&1 && command -v xbps-uhelper >/dev/null 2>&1; then printf xbps; fi"
	}
	if fields := strings.Fields(mustProbe(ctx, tr, script)); len(fields) >= 1 && fields[0] == manager {
		// The probe itself tests the paired database executable before writing
		// the manager token. The second token makes real facts self-describing;
		// accepting the historical single token keeps existing fake transports
		// compatible without weakening the target-side probe.
		return manager, database
	}
	return "unknown", ""
}

func inspectSELinux(ctx context.Context, tr transport.Transport) facts.SELinux {
	return facts.SELinux{Mode: facts.NormalizeSELinuxMode(mustProbe(ctx, tr, "if command -v getenforce >/dev/null 2>&1; then getenforce; fi"))}
}

func inspectManagedMountConfigs(ctx context.Context, tr transport.Transport, resources []config.StorageResource) []facts.StorageMountConfig {
	result := make([]facts.StorageMountConfig, 0)
	for _, resource := range resources {
		if !resource.ManagedMount {
			continue
		}
		result = append(result, facts.StorageMountConfig{Name: resource.Name, State: storagepolicy.MountConfigState(resource, mustProbe(ctx, tr, storagepolicy.MountConfigProbe(resource)))})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// mustProbe returns an empty string on a missing optional capability. Failure of
// mandatory discovery is handled above; optional capability absence is state.
func mustProbe(ctx context.Context, tr transport.Transport, script string) string {
	result, err := tr.Run(ctx, transport.Request{Script: script})
	if err != nil {
		return ""
	}
	return strings.TrimSpace(result.Stdout)
}

func inspectSSH(ctx context.Context, tr transport.Transport, init facts.InitSystem) facts.SSH {
	if init == facts.InitSystemOpenRC {
		return inspectOpenRCSSH(ctx, tr)
	}
	if init == facts.InitSystemRunit {
		return inspectRunitSSH(ctx, tr)
	}
	if init == facts.InitSystemSysV {
		return inspectSysVSSH(ctx, tr)
	}
	if init == facts.InitSystemDinit {
		return inspectDinitSSH(ctx, tr)
	}
	lines := probeLines(ctx, tr, `
if command -v sshd >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl cat ssh.service >/dev/null 2>&1; then printf 'service=ssh.service\n'; elif systemctl cat sshd.service >/dev/null 2>&1; then printf 'service=sshd.service\n'; else printf 'service=\n'; fi
service=$(systemctl cat ssh.service >/dev/null 2>&1 && printf ssh.service || (systemctl cat sshd.service >/dev/null 2>&1 && printf sshd.service || true))
if test -n "$service" && systemctl is-enabled "$service" >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if test -n "$service" && systemctl is-active "$service" >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then printf 'valid=yes\n'; else printf 'valid=no\n'; fi
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf([[:space:]]|$)' /etc/ssh/sshd_config 2>/dev/null; then printf 'dropin=yes\n'; else printf 'dropin=no\n'; fi
first=$(find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -printf '%f\n' 2>/dev/null | LC_ALL=C sort | head -n 1)
printf 'first=%s\n' "$first"
if sshd -T 2>/dev/null | grep -Fqx 'permitrootlogin no' && sshd -T 2>/dev/null | grep -Fqx 'passwordauthentication no'; then printf 'effective=yes\n'; else printf 'effective=no\n'; fi
home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)
if test -n "$home" && test -s "$home/.ssh/authorized_keys"; then printf 'keys=yes\n'; else printf 'keys=no\n'; fi
`)
	return facts.SSH{Installed: lines["installed"] == "yes", Service: lines["service"], ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", ConfigValid: lines["valid"] == "yes", DropInSupported: lines["dropin"] == "yes", FirstDropIn: lines["first"], HardeningEffective: lines["effective"] == "yes", AuthorizedKeysPresent: lines["keys"] == "yes", BebopDropIn: mustProbe(ctx, tr, "if test -r /etc/ssh/sshd_config.d/00-bebop.conf; then cat /etc/ssh/sshd_config.d/00-bebop.conf; fi")}
}

func inspectSysVSSH(ctx context.Context, tr transport.Transport) facts.SSH {
	lines := probeLines(ctx, tr, `
if command -v sshd >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test -x /etc/init.d/ssh; then printf 'service=sysv:ssh\n'; else printf 'service=\n'; fi
enabled=no
for link in /etc/rc[2345].d/S??ssh; do
  test -L "$link" && test "$(readlink -f "$link")" = /etc/init.d/ssh || continue
  enabled=yes
  break
done
printf 'enabled=%s\n' "$enabled"
if test -x /etc/init.d/ssh && service ssh status >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then printf 'valid=yes\n'; else printf 'valid=no\n'; fi
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\\*\\.conf([[:space:]]|$)' /etc/ssh/sshd_config 2>/dev/null; then printf 'dropin=yes\n'; else printf 'dropin=no\n'; fi
first=$(for candidate in /etc/ssh/sshd_config.d/*.conf; do test -f "$candidate" && basename "$candidate"; done | LC_ALL=C sort | head -n 1)
printf 'first=%s\n' "$first"
if sshd -T 2>/dev/null | grep -Fqx 'permitrootlogin no' && sshd -T 2>/dev/null | grep -Fqx 'passwordauthentication no'; then printf 'effective=yes\n'; else printf 'effective=no\n'; fi
home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)
if test -n "$home" && test -s "$home/.ssh/authorized_keys"; then printf 'keys=yes\n'; else printf 'keys=no\n'; fi`)
	return facts.SSH{Installed: lines["installed"] == "yes", Service: lines["service"], ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", ConfigValid: lines["valid"] == "yes", DropInSupported: lines["dropin"] == "yes", FirstDropIn: lines["first"], HardeningEffective: lines["effective"] == "yes", AuthorizedKeysPresent: lines["keys"] == "yes", BebopDropIn: mustProbe(ctx, tr, "if test -r /etc/ssh/sshd_config.d/00-bebop.conf; then cat /etc/ssh/sshd_config.d/00-bebop.conf; fi")}
}

func inspectDinitSSH(ctx context.Context, tr transport.Transport) facts.SSH {
	lines := probeLines(ctx, tr, `
if command -v sshd >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test -f /etc/dinit.d/sshd && test -d /etc/dinit.d/boot.d; then printf 'service=dinit:sshd\n'; else printf 'service=\n'; fi
if test -L /etc/dinit.d/boot.d/sshd && test "$(readlink -f /etc/dinit.d/boot.d/sshd)" = /etc/dinit.d/sshd; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if dinitctl -s is-started sshd >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then printf 'valid=yes\n'; else printf 'valid=no\n'; fi
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\\*\\.conf([[:space:]]|$)' /etc/ssh/sshd_config 2>/dev/null; then printf 'dropin=yes\n'; else printf 'dropin=no\n'; fi
first=$(for candidate in /etc/ssh/sshd_config.d/*.conf; do test -f "$candidate" && basename "$candidate"; done | LC_ALL=C sort | head -n 1)
printf 'first=%s\n' "$first"
if sshd -T 2>/dev/null | grep -Fqx 'permitrootlogin no' && sshd -T 2>/dev/null | grep -Fqx 'passwordauthentication no'; then printf 'effective=yes\n'; else printf 'effective=no\n'; fi
home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)
if test -n "$home" && test -s "$home/.ssh/authorized_keys"; then printf 'keys=yes\n'; else printf 'keys=no\n'; fi`)
	return facts.SSH{Installed: lines["installed"] == "yes", Service: lines["service"], ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", ConfigValid: lines["valid"] == "yes", DropInSupported: lines["dropin"] == "yes", FirstDropIn: lines["first"], HardeningEffective: lines["effective"] == "yes", AuthorizedKeysPresent: lines["keys"] == "yes", BebopDropIn: mustProbe(ctx, tr, "if test -r /etc/ssh/sshd_config.d/00-bebop.conf; then cat /etc/ssh/sshd_config.d/00-bebop.conf; fi")}
}

func inspectOpenRCSSH(ctx context.Context, tr transport.Transport) facts.SSH {
	lines := probeLines(ctx, tr, `
if command -v sshd >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test -x /etc/init.d/sshd; then printf 'service=sshd\n'; else printf 'service=\n'; fi
if test -x /etc/init.d/sshd && rc-update show default 2>/dev/null | grep -Eq '^[[:space:]]*sshd([[:space:]]|$)'; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if test -x /etc/init.d/sshd && rc-service sshd status >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then printf 'valid=yes\n'; else printf 'valid=no\n'; fi
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf([[:space:]]|$)' /etc/ssh/sshd_config 2>/dev/null; then printf 'dropin=yes\n'; else printf 'dropin=no\n'; fi
first=$(for candidate in /etc/ssh/sshd_config.d/*.conf; do test -f "$candidate" && basename "$candidate"; done | LC_ALL=C sort | head -n 1)
printf 'first=%s\n' "$first"
if sshd -T 2>/dev/null | grep -Fqx 'permitrootlogin no' && sshd -T 2>/dev/null | grep -Fqx 'passwordauthentication no'; then printf 'effective=yes\n'; else printf 'effective=no\n'; fi
home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)
if test -n "$home" && test -s "$home/.ssh/authorized_keys"; then printf 'keys=yes\n'; else printf 'keys=no\n'; fi`)
	return facts.SSH{Installed: lines["installed"] == "yes", Service: lines["service"], ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", ConfigValid: lines["valid"] == "yes", DropInSupported: lines["dropin"] == "yes", FirstDropIn: lines["first"], HardeningEffective: lines["effective"] == "yes", AuthorizedKeysPresent: lines["keys"] == "yes", BebopDropIn: mustProbe(ctx, tr, "if test -r /etc/ssh/sshd_config.d/00-bebop.conf; then cat /etc/ssh/sshd_config.d/00-bebop.conf; fi")}
}

func inspectRunitSSH(ctx context.Context, tr transport.Transport) facts.SSH {
	lines := probeLines(ctx, tr, `
if command -v sshd >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test -d /etc/sv/sshd && ! test -L /etc/sv/sshd; then printf 'service=sshd\n'; else printf 'service=\n'; fi
if test -L /var/service/sshd && test "$(readlink -f /var/service/sshd)" = "$(readlink -f /etc/sv/sshd)"; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if test -d /etc/sv/sshd && ! test -L /etc/sv/sshd && sv status sshd 2>/dev/null | grep -Eq '^run:'; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v sshd >/dev/null 2>&1 && sshd -t >/dev/null 2>&1; then printf 'valid=yes\n'; else printf 'valid=no\n'; fi
if grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf([[:space:]]|$)' /etc/ssh/sshd_config 2>/dev/null; then printf 'dropin=yes\n'; else printf 'dropin=no\n'; fi
first=$(for candidate in /etc/ssh/sshd_config.d/*.conf; do test -f "$candidate" && basename "$candidate"; done | LC_ALL=C sort | head -n 1)
printf 'first=%s\n' "$first"
if sshd -T 2>/dev/null | grep -Fqx 'permitrootlogin no' && sshd -T 2>/dev/null | grep -Fqx 'passwordauthentication no'; then printf 'effective=yes\n'; else printf 'effective=no\n'; fi
home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)
if test -n "$home" && test -s "$home/.ssh/authorized_keys"; then printf 'keys=yes\n'; else printf 'keys=no\n'; fi`)
	service := lines["service"]
	if service == "sshd" {
		service = "runit:sshd"
	}
	return facts.SSH{Installed: lines["installed"] == "yes", Service: service, ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", ConfigValid: lines["valid"] == "yes", DropInSupported: lines["dropin"] == "yes", FirstDropIn: lines["first"], HardeningEffective: lines["effective"] == "yes", AuthorizedKeysPresent: lines["keys"] == "yes", BebopDropIn: mustProbe(ctx, tr, "if test -r /etc/ssh/sshd_config.d/00-bebop.conf; then cat /etc/ssh/sshd_config.d/00-bebop.conf; fi")}
}

func inspectDocker(ctx context.Context, tr transport.Transport, init facts.InitSystem, packageManager string, os facts.OS) facts.Docker {
	systemd := init == facts.InitSystemSystemd
	if packageManager == "apk" && os.Family == "alpine" {
		return inspectAlpineDocker(ctx, tr)
	}
	if packageManager == "xbps" && os.Family == "void" {
		return inspectVoidDocker(ctx, tr)
	}
	if packageManager == "apt" && os.Family == "devuan" {
		return inspectDevuanDocker(ctx, tr)
	}
	if packageManager == "pacman" && os.Family == "arch" {
		return inspectArchDocker(ctx, tr, systemd)
	}
	if packageManager == "pacman" && os.Family == "artix" {
		return inspectArtixDocker(ctx, tr)
	}
	script := `
if dpkg-query -W -f='${db:Status-Status}' docker.io 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
if apt-cache show docker-compose-plugin >/dev/null 2>&1; then printf 'compose_package=docker-compose-plugin\n'; elif apt-cache show docker-compose-v2 >/dev/null 2>&1; then printf 'compose_package=docker-compose-v2\n'; else printf 'compose_package=\n'; fi
`
	if packageManager == "dnf5" {
		script = `
if rpm -q moby-engine >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if rpm -q moby-engine docker-cli docker-compose >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if dnf5 repoquery --available --queryformat '%{name}\n' moby-engine 2>/dev/null | grep -qx moby-engine && dnf5 repoquery --available --queryformat '%{name}\n' docker-cli 2>/dev/null | grep -qx docker-cli && dnf5 repoquery --available --queryformat '%{name}\n' docker-compose 2>/dev/null | grep -qx docker-compose; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
for package in docker-ce docker-ce-cli containerd.io; do if rpm -q "$package" >/dev/null 2>&1; then printf 'conflict=yes\n'; fi; done
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
if dnf5 repoquery --available docker-compose >/dev/null 2>&1; then printf 'compose_package=docker-compose\n'; else printf 'compose_package=\n'; fi
`
	}
	if packageManager == "zypper" && os.Family == "opensuse" {
		return inspectOpenSUSEDocker(ctx, tr, systemd)
	}
	policy := ""
	if packageManager == "dnf" {
		family, major, ok := facts.DockerCERepositoryPolicy(os)
		if !ok {
			return facts.Docker{}
		}
		policy = family + "-" + major
		script = enterpriseDockerProbeScript(family, major)
	}
	lines := probeLines(ctx, tr, script)
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: lines["package_available"] == "yes", ConflictingPackages: lines["conflict"] == "yes", RepositoryState: lines["repository"], RepositoryPolicy: policy, ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: lines["compose_package"]}
}

// devuanDockerCandidateScript accepts only codename-pinned Devuan merged
// candidates. A same-version candidate from another source is deliberately a
// conflict rather than an authority Bebop silently adopts.
const devuanDockerCandidateScript = `for package in docker.io docker-compose; do
  candidate=$(LC_ALL=C apt-cache policy "$package" 2>/dev/null | awk '/^[[:space:]]*Candidate:/ { print $2; exit }')
  test -n "$candidate" && test "$candidate" != '(none)' || exit 1
  LC_ALL=C apt-cache madison "$package" 2>/dev/null | awk -v version="$candidate" '
    $3 == version { seen=1; if ($5 != "http://deb.devuan.org/merged" || $6 !~ /^excalibur(-updates|-security)?\//) bad=1; else good=1 }
    END { exit !(seen && good && !bad) }'
done`

func inspectDevuanDocker(ctx context.Context, tr transport.Transport) facts.Docker {
	lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' docker.io 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if dpkg-query -W -f='${db:Status-Status}' docker.io docker-compose 2>/dev/null | grep -qx installed; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if `+devuanDockerCandidateScript+`; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
enabled=no
if test -x /etc/init.d/docker; then
  for link in /etc/rc[2345].d/S??docker; do
    test -L "$link" && test "$(readlink -f "$link")" = /etc/init.d/docker || continue
    enabled=yes
    break
  done
fi
printf 'enabled=%s\n' "$enabled"
if test -x /etc/init.d/docker && service docker status >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi`)
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: lines["package_available"] == "yes", RepositoryPolicy: "devuan-excalibur", ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: "docker-compose", ServiceDefinition: lines["installed"] == "yes"}
}

func inspectArtixDocker(ctx context.Context, tr transport.Transport) facts.Docker {
	lines := probeLines(ctx, tr, `
if pacman -Q docker >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if pacman -Q docker docker-compose docker-dinit >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if for package in docker docker-compose docker-dinit; do LC_ALL=C pacman -Si world/$package 2>/dev/null | awk -F ' *: *' '$1 == "Repository" { found=($2 == "world") } END { exit !found }' || exit 1; done; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if test -f /etc/dinit.d/dockerd && test -d /etc/dinit.d/boot.d; then printf 'service_definition=yes\n'; else printf 'service_definition=no\n'; fi
if test -L /etc/dinit.d/boot.d/dockerd && test "$(readlink -f /etc/dinit.d/boot.d/dockerd)" = /etc/dinit.d/dockerd; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if dinitctl -s is-started dockerd >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if test -r /sys/fs/cgroup/cgroup.controllers; then printf 'cgroups=yes\n'; else printf 'cgroups=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi`)
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: lines["package_available"] == "yes", RepositoryPolicy: "artix-world", ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: "docker-compose", CgroupsAvailable: lines["cgroups"] == "yes", ServiceDefinition: lines["service_definition"] == "yes", ServiceLinkState: lines["enabled"]}
}

const alpineBebopRepositoriesPath = "/etc/apk/repositories.d/50-bebop.list"

const alpineBebopRepositories = `# Managed by Bebop. Manual edits may be replaced.
v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main
v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community
v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main
v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community`

func inspectAlpineDocker(ctx context.Context, tr transport.Transport) facts.Docker {
	lines := probeLines(ctx, tr, `
if apk info -e docker >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if apk info -e docker docker-cli-compose docker-openrc >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if for package in docker docker-cli-compose docker-openrc; do apk policy "$package" 2>/dev/null | grep -Fq 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' || exit 1; done; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if test ! -e `+transport.ShellQuote(alpineBebopRepositoriesPath)+`; then printf 'repository=absent\n'; elif test "$(cat `+transport.ShellQuote(alpineBebopRepositoriesPath)+`)" = "$(printf '%s\\n' `+transport.ShellQuote(alpineBebopRepositories)+`)"; then printf 'repository=managed\n'; else printf 'repository=unmanaged\n'; fi
if test -x /etc/init.d/docker && rc-update show default 2>/dev/null | grep -Eq '^[[:space:]]*docker([[:space:]]|$)'; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if test -x /etc/init.d/docker && rc-service docker status >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if test -r /sys/fs/cgroup/cgroup.controllers; then printf 'cgroups=yes\n'; else printf 'cgroups=no\n'; fi
if test -x /etc/init.d/cgroups; then printf 'cgroups_service=yes\n'; else printf 'cgroups_service=no\n'; fi
if test -x /etc/init.d/cgroups && rc-update show default 2>/dev/null | grep -Eq '^[[:space:]]*cgroups([[:space:]]|$)'; then printf 'cgroups_enabled=yes\n'; else printf 'cgroups_enabled=no\n'; fi
if test -x /etc/init.d/cgroups && rc-service cgroups status >/dev/null 2>&1; then printf 'cgroups_active=yes\n'; else printf 'cgroups_active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi`)
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: lines["package_available"] == "yes", RepositoryState: lines["repository"], RepositoryPolicy: "alpine-v3.24", ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: "docker-cli-compose", CgroupsAvailable: lines["cgroups"] == "yes", CgroupsServiceExists: lines["cgroups_service"] == "yes", CgroupsServiceEnabled: lines["cgroups_enabled"] == "yes", CgroupsServiceActive: lines["cgroups_active"] == "yes"}
}

// inspectVoidDocker keeps the selected package source explicit. Repository
// indexes are read into XBPS memory only; no operator repository configuration
// participates in the availability decision for Bebop-managed packages.
func inspectVoidDocker(ctx context.Context, tr transport.Transport) facts.Docker {
	return inspectVoidDockerFor(ctx, tr, voidRepositoryFromNative(ctx, tr))
}

func voidRepositoryFromNative(ctx context.Context, tr transport.Transport) string {
	architecture, libc, ok := facts.NormalizeVoidArchitecture(firstLine(mustProbe(ctx, tr, "xbps-uhelper arch")))
	if !ok {
		return ""
	}
	repository, _ := facts.VoidRepository(architecture, libc)
	return repository
}

func inspectVoidDockerFor(ctx context.Context, tr transport.Transport, repository string) facts.Docker {
	if repository == "" {
		return facts.Docker{RepositoryPolicy: "void-official"}
	}
	lines := probeLines(ctx, tr, `
if xbps-query -p pkgver docker >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if xbps-query -p pkgver docker >/dev/null 2>&1 && xbps-query -p pkgver docker-compose >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if xbps-query -p pkgver docker >/dev/null 2>&1 || xbps-query -p pkgver docker-compose >/dev/null 2>&1; then
  if { ! xbps-query -p pkgver docker >/dev/null 2>&1 || xbps-query -p repository docker 2>/dev/null | grep -Fqx `+transport.ShellQuote(repository)+`; } && { ! xbps-query -p pkgver docker-compose >/dev/null 2>&1 || xbps-query -p repository docker-compose 2>/dev/null | grep -Fqx `+transport.ShellQuote(repository)+`; }; then printf 'repository=reviewed\n'; else printf 'repository=unmanaged\n'; fi
else printf 'repository=absent\n'; fi
if xbps-query --ignore-conf-repos --repository=`+transport.ShellQuote(repository)+` -M -S docker >/dev/null 2>&1 && xbps-query --ignore-conf-repos --repository=`+transport.ShellQuote(repository)+` -M -S docker-compose >/dev/null 2>&1; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if xbps-query -H 2>/dev/null | grep -Eq '(^|[[:space:]])(docker|docker-compose)([<>=~][^[:space:]]*)?([[:space:]]|$)'; then printf 'held=yes\n'; else printf 'held=no\n'; fi
if xbps-query --list-repolock-pkgs 2>/dev/null | grep -Eq '(^|[[:space:]])(docker|docker-compose)([<>=~][^[:space:]]*)?([[:space:]]|$)'; then printf 'repolocked=yes\n'; else printf 'repolocked=no\n'; fi
if test -d /etc/sv/docker && ! test -L /etc/sv/docker; then printf 'service_definition=yes\n'; else printf 'service_definition=no\n'; fi
if test -L /var/service/docker && test "$(readlink -f /var/service/docker)" = "$(readlink -f /etc/sv/docker)"; then printf 'service_link=correct\n'; elif test -e /var/service/docker || test -L /var/service/docker; then printf 'service_link=conflict\n'; else printf 'service_link=absent\n'; fi
if test -d /etc/sv/docker && ! test -L /etc/sv/docker && sv status docker 2>/dev/null | grep -Eq '^run:'; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; } || { command -v sudo >/dev/null 2>&1 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; } || { command -v doas >/dev/null 2>&1 && doas -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
if test -r /sys/fs/cgroup/cgroup.controllers; then printf 'cgroups=yes\n'; else printf 'cgroups=no\n'; fi`)
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: lines["package_available"] == "yes", RepositoryState: lines["repository"], RepositoryPolicy: repository, ServiceEnabled: lines["service_link"] == "correct", ServiceActive: lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: "docker-compose", CgroupsAvailable: lines["cgroups"] == "yes", ServiceDefinition: lines["service_definition"] == "yes", ServiceLinkState: lines["service_link"], PackageHeld: lines["held"] == "yes", PackageRepolocked: lines["repolocked"] == "yes"}
}

// inspectArchDocker queries only Pacman's existing sync database. In
// particular, pacman -Si does not synchronize /var/lib/pacman/sync, so this
// probe can determine whether the reviewed official packages are available
// without creating a partial-upgrade state.
func inspectArchDocker(ctx context.Context, tr transport.Transport, systemd bool) facts.Docker {
	lines := probeLines(ctx, tr, `
if pacman -Q docker >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if pacman -Q docker docker-compose >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if LC_ALL=C pacman -Si docker 2>/dev/null | awk -F ' *: *' 'function finish() { if (name != "") { if (name == "docker" && (repository == "core" || repository == "extra" || repository == "multilib")) count++; else invalid=1; name=""; repository="" } } $1 == "Repository" { finish(); repository=$2 } $1 == "Name" { name=$2 } END { finish(); exit !(count == 1 && !invalid) }' && LC_ALL=C pacman -Si docker-compose 2>/dev/null | awk -F ' *: *' 'function finish() { if (name != "") { if (name == "docker-compose" && (repository == "core" || repository == "extra" || repository == "multilib")) count++; else invalid=1; name=""; repository="" } } $1 == "Repository" { finish(); repository=$2 } $1 == "Name" { name=$2 } END { finish(); exit !(count == 1 && !invalid) }'; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
`)
	composePackage := ""
	if lines["package_available"] == "yes" {
		composePackage = "docker-compose"
	}
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: lines["package_available"] == "yes", RepositoryPolicy: "arch-official", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: composePackage}
}

// inspectOpenSUSEDocker accepts only packages resolved from enabled official
// openSUSE repositories. It consumes Zypper XML only long enough to normalize
// availability; raw repository metadata never becomes a host fact.
func inspectOpenSUSEDocker(ctx context.Context, tr transport.Transport, systemd bool) facts.Docker {
	lines := probeLines(ctx, tr, `
if rpm -q docker >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if rpm -q docker docker-compose >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
for package in docker-ce docker-ce-cli docker-compose-plugin; do if rpm -q "$package" >/dev/null 2>&1; then printf 'conflict=yes\n'; fi; done
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
`)
	repositories := mustProbe(ctx, tr, "zypper --non-interactive --no-refresh --xmlout lr -u 2>/dev/null || true")
	packages := mustProbe(ctx, tr, "zypper --non-interactive --no-refresh --xmlout search --details docker docker-compose 2>/dev/null || true")
	available := openSUSEPackagesAvailable(repositories, packages, "docker", "docker-compose")
	composePackage := ""
	if openSUSEPackagesAvailable(repositories, packages, "docker-compose") {
		composePackage = "docker-compose"
	}
	return facts.Docker{Installed: lines["installed"] == "yes", PackageSetComplete: lines["package_set"] == "yes", PackageSetAvailable: available, ConflictingPackages: lines["conflict"] == "yes", RepositoryPolicy: "opensuse-official", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: composePackage}
}

type zypperRepositoryList struct {
	Repositories []struct {
		Alias           string `xml:"alias,attr"`
		Name            string `xml:"name,attr"`
		Enabled         string `xml:"enabled,attr"`
		GPGCheck        string `xml:"gpgcheck,attr"`
		RepoGPGCheck    string `xml:"repo_gpgcheck,attr"`
		PackageGPGCheck string `xml:"pkg_gpgcheck,attr"`
		URL             string `xml:"url"`
	} `xml:"repo-list>repo"`
}

type zypperSearchResult struct {
	Packages []struct {
		Name       string `xml:"name,attr"`
		Kind       string `xml:"kind,attr"`
		Repository string `xml:"repository,attr"`
	} `xml:"search-result>solvable-list>solvable"`
}

func openSUSEPackagesAvailable(repoXML, packagesXML string, required ...string) bool {
	var repositories zypperRepositoryList
	var packages zypperSearchResult
	if xml.Unmarshal([]byte(repoXML), &repositories) != nil || xml.Unmarshal([]byte(packagesXML), &packages) != nil {
		return false
	}
	allowed := make(map[string]bool)
	for _, repository := range repositories.Repositories {
		parsed, err := url.Parse(strings.TrimSpace(repository.URL))
		if err != nil || repository.Enabled != "1" || repository.GPGCheck != "1" || repository.RepoGPGCheck != "1" || repository.PackageGPGCheck != "1" || !strings.HasPrefix(repository.Alias, "openSUSE:") || !officialOpenSUSERepositoryHost(parsed.Hostname()) {
			continue
		}
		allowed[repository.Name] = true
	}
	found := make(map[string]bool)
	for _, candidate := range packages.Packages {
		if candidate.Kind == "package" && allowed[candidate.Repository] {
			for _, name := range required {
				if candidate.Name == name {
					found[name] = true
				}
			}
		}
	}
	for _, name := range required {
		if !found[name] {
			return false
		}
	}
	return true
}

func officialOpenSUSERepositoryHost(host string) bool {
	switch strings.ToLower(host) {
	case "cdn.opensuse.org", "download.opensuse.org", "downloadcontent.opensuse.org":
		return true
	default:
		return false
	}
}

func enterpriseDockerProbeScript(family, major string) string {
	baseURL := "https://download.docker.com/linux/" + family + "/" + major + "/$basearch/stable"
	keyURL := "https://download.docker.com/linux/" + family + "/gpg"
	repository := rpmRepositoryStateProbe("/etc/yum.repos.d/docker-ce-stable.repo", []string{
		"# Managed by Bebop. Manual edits may be replaced.",
		"[docker-ce-stable]",
		"baseurl=" + baseURL,
		"enabled=1",
		"gpgcheck=1",
		"gpgkey=" + keyURL,
	}, "download.docker.com/linux/")
	return `
if rpm -q docker-ce >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if rpm -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if dnf repoquery --available --queryformat '%{name}\n' docker-ce 2>/dev/null | grep -qx docker-ce && dnf repoquery --available --queryformat '%{name}\n' docker-ce-cli 2>/dev/null | grep -qx docker-ce-cli && dnf repoquery --available --queryformat '%{name}\n' containerd.io 2>/dev/null | grep -qx containerd.io && dnf repoquery --available --queryformat '%{name}\n' docker-buildx-plugin 2>/dev/null | grep -qx docker-buildx-plugin && dnf repoquery --available --queryformat '%{name}\n' docker-compose-plugin 2>/dev/null | grep -qx docker-compose-plugin; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
for package in moby-engine moby-cli docker containerd; do if rpm -q "$package" >/dev/null 2>&1; then printf 'conflict=yes\n'; fi; done
` + repository + `
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
if dnf repoquery --available docker-compose-plugin >/dev/null 2>&1; then printf 'compose_package=docker-compose-plugin\n'; else printf 'compose_package=\n'; fi
`
}

// rpmRepositoryStateProbe emits only a normalized ownership state. The
// expected values are fixed reviewed literals selected by the OS policy.
func rpmRepositoryStateProbe(repoPath string, required []string, repositoryHost string) string {
	quotedPath := transport.ShellQuote(repoPath)
	checks := make([]string, 0, len(required))
	for _, line := range required {
		checks = append(checks, "grep -Fqx "+transport.ShellQuote(line)+" "+quotedPath+" 2>/dev/null")
	}
	return "if test ! -e " + quotedPath + `; then
  found=no
  for candidate in /etc/yum.repos.d/*.repo; do
    test -f "$candidate" || continue
    test "$candidate" = ` + quotedPath + ` && continue
    if grep -Fq ` + transport.ShellQuote(repositoryHost) + ` "$candidate" 2>/dev/null; then found=yes; fi
  done
  if test "$found" = yes; then printf 'repository=unmanaged\n'; else printf 'repository=absent\n'; fi
elif ` + strings.Join(checks, " && ") + `; then
  found=no
  for candidate in /etc/yum.repos.d/*.repo; do
    test -f "$candidate" || continue
    test "$candidate" = ` + quotedPath + ` && continue
    if grep -Fq ` + transport.ShellQuote(repositoryHost) + ` "$candidate" 2>/dev/null; then found=yes; fi
  done
  if test "$found" = yes; then printf 'repository=unmanaged\n'; else printf 'repository=managed\n'; fi
else
  printf 'repository=unmanaged\n'
fi`
}

func inspectServices(ctx context.Context, tr transport.Transport, dataRoot string, deployments []services.Deployment, dockerResponsive bool) []facts.Service {
	result := make([]facts.Service, 0, len(deployments))
	for _, deployment := range deployments {
		service := facts.Service{Name: deployment.Name, Project: deployment.Project, DesiredState: deployment.State, Runtime: "unknown", Health: "unknown"}
		root := path.Join(dataRoot, "services", deployment.Name)
		current := path.Join(root, "current")
		lines := probeLines(ctx, tr, deploymentProbeScript(root, current, deployment.ComposeFile))
		service.DeploymentPresent = lines["deployment"] == "yes"
		service.DeploymentUnsafe = lines["unsafe"] == "yes"
		service.DeploymentDigest = lines["digest"]
		service.SecretFingerprint = lines["secret_fingerprint"]
		service.PlacementFingerprint = lines["placement_fingerprint"]
		if dockerResponsive {
			service.Runtime, service.Health, service.ContainerCount = inspectServiceRuntime(ctx, tr, deployment.Project)
		} else if !service.DeploymentPresent && !service.DeploymentUnsafe {
			service.Runtime, service.Health = "missing", "missing"
		}
		result = append(result, service)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func deploymentProbeScript(root, current, composeFile string) string {
	quotedRoot := transport.ShellQuote(root)
	quotedCurrent := transport.ShellQuote(current)
	quotedCompose := transport.ShellQuote(composeFile)
	return `root=` + quotedRoot + `
current=` + quotedCurrent + `
if test -L "$current" && test -d "$current"; then
  resolved=$(readlink -f -- "$current" 2>/dev/null || true)
  case "$resolved" in "$root"/releases/*) ;; *) printf 'unsafe=yes\n'; exit 0;; esac
  if test ! -f "$current"/` + quotedCompose + `; then printf 'unsafe=yes\n'; exit 0; fi
  digest=$(cd -- "$current" && find . -type f ! -path './` + services.SecretEnvName + `' ! -path './` + services.SecretFingerprintName + `' ! -path './` + services.PlacementFingerprintName + `' -printf '%P\n' | LC_ALL=C sort | while IFS= read -r file; do
    test -n "$file" || continue
    mode=$(stat -c '%a' -- "$file")
    checksum=$(sha256sum -- "$file" | awk '{print $1}')
    printf '%s\t%s\t%s\n' "$mode" "$checksum" "$file"
  done | sha256sum | awk '{print $1}')
  printf 'deployment=yes\n'
  printf 'digest=%s\n' "$digest"
  if test -f "$current"/` + transport.ShellQuote(services.SecretFingerprintName) + `; then tr -d '\n' < "$current"/` + transport.ShellQuote(services.SecretFingerprintName) + ` | sed 's/^/secret_fingerprint=/'; else printf 'secret_fingerprint=\n'; fi
  if test -f "$current"/` + transport.ShellQuote(services.PlacementFingerprintName) + `; then tr -d '\n' < "$current"/` + transport.ShellQuote(services.PlacementFingerprintName) + ` | sed 's/^/placement_fingerprint=/'; else printf 'placement_fingerprint=\n'; fi
elif test -e "$current"; then
  printf 'unsafe=yes\n'
else
  printf 'deployment=no\n'
fi`
}

func inspectServiceRuntime(ctx context.Context, tr transport.Transport, project string) (string, string, int) {
	ids := strings.Fields(mustProbe(ctx, tr, "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default ps --all --filter label=com.docker.compose.project="+transport.ShellQuote(project)+" --format '{{.ID}}'"))
	if len(ids) == 0 {
		return "missing", "missing", 0
	}
	states := make([]dockerContainerState, 0, len(ids))
	for _, id := range ids {
		output := mustProbe(ctx, tr, "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default inspect --format '{{json .State}}' -- "+transport.ShellQuote(id))
		var state dockerContainerState
		if output == "" || json.Unmarshal([]byte(output), &state) != nil {
			return "unknown", "unknown", len(ids)
		}
		states = append(states, state)
	}
	return aggregateRuntime(states)
}

type dockerContainerState struct {
	Status     string `json:"Status"`
	Running    bool   `json:"Running"`
	Restarting bool   `json:"Restarting"`
	Dead       bool   `json:"Dead"`
	Health     *struct {
		Status string `json:"Status"`
	} `json:"Health"`
}

func aggregateRuntime(states []dockerContainerState) (string, string, int) {
	if len(states) == 0 {
		return "missing", "missing", 0
	}
	allStopped := true
	allRunning := true
	anyStarting := false
	anyUnhealthy := false
	anyHealthcheck := false
	allHealthy := true
	for _, state := range states {
		if state.Running {
			allStopped = false
		} else {
			allRunning = false
		}
		if state.Restarting || state.Status == "created" {
			anyStarting = true
		}
		if state.Dead || (state.Health != nil && state.Health.Status == "unhealthy") {
			anyUnhealthy = true
		}
		if state.Health != nil {
			anyHealthcheck = true
			if state.Health.Status == "starting" {
				anyStarting = true
			}
			if state.Health.Status != "healthy" {
				allHealthy = false
			}
		}
	}
	if anyUnhealthy {
		return "unhealthy", "unhealthy", len(states)
	}
	if anyStarting {
		return "starting", "starting", len(states)
	}
	if allStopped {
		return "stopped", "stopped", len(states)
	}
	if !allRunning {
		return "unknown", "unknown", len(states)
	}
	if !anyHealthcheck {
		return "running", "no-healthcheck", len(states)
	}
	if allHealthy {
		return "running", "healthy", len(states)
	}
	return "starting", "starting", len(states)
}

func inspectTailscale(ctx context.Context, tr transport.Transport, init facts.InitSystem, packageManager string, os facts.OS) facts.Tailscale {
	systemd := init == facts.InitSystemSystemd
	if packageManager == "apk" && os.Family == "alpine" {
		return inspectAlpineTailscale(ctx, tr)
	}
	if packageManager == "xbps" && os.Family == "void" {
		return inspectVoidTailscale(ctx, tr)
	}
	if packageManager == "pacman" && os.Family == "arch" {
		return inspectArchTailscale(ctx, tr, systemd)
	}
	if packageManager == "apt" && os.Family == "devuan" {
		return inspectDevuanTailscale(ctx, tr)
	}
	if packageManager == "pacman" && os.Family == "artix" {
		return inspectArtixTailscale(ctx, tr)
	}
	script := `
if dpkg-query -W -f='${db:Status-Status}' tailscale 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled tailscaled.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active tailscaled.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
`
	if packageManager == "dnf5" {
		script = `
if rpm -q tailscale >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled tailscaled.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active tailscaled.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if test ! -e /etc/yum.repos.d/tailscale.repo; then printf 'repository=absent\n'; elif grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/yum.repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'baseurl=https://pkgs.tailscale.com/stable/fedora/$basearch' /etc/yum.repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'gpgcheck=1' /etc/yum.repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'repo_gpgcheck=1' /etc/yum.repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'gpgkey=https://pkgs.tailscale.com/stable/fedora/repo.gpg' /etc/yum.repos.d/tailscale.repo 2>/dev/null; then printf 'repository=managed\n'; else printf 'repository=unmanaged\n'; fi
`
	}
	if packageManager == "dnf" {
		family, major, ok := facts.TailscaleRPMRepositoryPolicy(os)
		if !ok {
			return facts.Tailscale{}
		}
		baseURL := "https://pkgs.tailscale.com/stable/" + family + "/" + major + "/$basearch"
		keyURL := "https://pkgs.tailscale.com/stable/" + family + "/" + major + "/repo.gpg"
		script = `
if rpm -q tailscale >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled tailscaled.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active tailscaled.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
` + rpmRepositoryStateProbe("/etc/yum.repos.d/tailscale.repo", []string{
			"# Managed by Bebop. Manual edits may be replaced.",
			"[tailscale-stable]",
			"baseurl=" + baseURL,
			"enabled=1",
			"gpgcheck=1",
			"repo_gpgcheck=1",
			"gpgkey=" + keyURL,
		}, "pkgs.tailscale.com/stable/")
	}
	if packageManager == "zypper" && os.Family == "opensuse" {
		repository, ok := facts.OpenSUSETailscaleRepositoryPolicy(os)
		if !ok {
			return facts.Tailscale{}
		}
		baseURL := "https://pkgs.tailscale.com/" + repository + "/$basearch"
		keyURL := "https://pkgs.tailscale.com/" + repository + "/repo.gpg"
		script = `
if rpm -q tailscale >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled tailscaled.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active tailscaled.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if test ! -e /etc/zypp/repos.d/tailscale.repo; then printf 'repository=absent\n'; elif grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/zypp/repos.d/tailscale.repo 2>/dev/null && grep -Fqx ` + transport.ShellQuote("baseurl="+baseURL) + ` /etc/zypp/repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'enabled=1' /etc/zypp/repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'gpgcheck=1' /etc/zypp/repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'repo_gpgcheck=1' /etc/zypp/repos.d/tailscale.repo 2>/dev/null && grep -Fqx 'pkg_gpgcheck=1' /etc/zypp/repos.d/tailscale.repo 2>/dev/null && grep -Fqx ` + transport.ShellQuote("gpgkey="+keyURL) + ` /etc/zypp/repos.d/tailscale.repo 2>/dev/null; then printf 'repository=managed\n'; else printf 'repository=unmanaged\n'; fi
`
	}
	lines := probeLines(ctx, tr, script)
	status := struct {
		BackendState string `json:"BackendState"`
		Self         *struct {
			Online bool `json:"Online"`
		} `json:"Self"`
	}{}
	_ = json.Unmarshal([]byte(mustProbe(ctx, tr, "if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null || true; fi")), &status)
	connected := status.BackendState == "Running" && status.Self != nil && status.Self.Online
	return facts.Tailscale{Installed: lines["installed"] == "yes", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Connected: connected, BackendState: status.BackendState, RepositoryState: lines["repository"]}
}

func inspectAlpineTailscale(ctx context.Context, tr transport.Transport) facts.Tailscale {
	lines := probeLines(ctx, tr, `
if apk info -e tailscale tailscale-openrc >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if for package in tailscale tailscale-openrc; do apk policy "$package" 2>/dev/null | grep -Fq 'https://dl-cdn.alpinelinux.org/alpine/v3.24/community' || exit 1; done; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if test ! -e `+transport.ShellQuote(alpineBebopRepositoriesPath)+`; then printf 'repository=absent\n'; elif test "$(cat `+transport.ShellQuote(alpineBebopRepositoriesPath)+`)" = "$(printf '%s\\n' `+transport.ShellQuote(alpineBebopRepositories)+`)"; then printf 'repository=managed\n'; else printf 'repository=unmanaged\n'; fi
if test -x /etc/init.d/tailscale && rc-update show default 2>/dev/null | grep -Eq '^[[:space:]]*tailscale([[:space:]]|$)'; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if test -x /etc/init.d/tailscale && rc-service tailscale status >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState":"\([^"]*\)".*/backend=\1/p' | head -n 1; fi`)
	return facts.Tailscale{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", Connected: lines["backend"] == "Running", BackendState: lines["backend"], RepositoryState: lines["repository"]}
}

func inspectVoidTailscale(ctx context.Context, tr transport.Transport) facts.Tailscale {
	repository := voidRepositoryFromNative(ctx, tr)
	if repository == "" {
		return facts.Tailscale{}
	}
	lines := probeLines(ctx, tr, `
if xbps-query -p pkgver tailscale >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if xbps-query -p pkgver tailscale >/dev/null 2>&1; then if xbps-query -p repository tailscale 2>/dev/null | grep -Fqx `+transport.ShellQuote(repository)+`; then printf 'repository=reviewed\n'; else printf 'repository=unmanaged\n'; fi; else printf 'repository=absent\n'; fi
if xbps-query --ignore-conf-repos --repository=`+transport.ShellQuote(repository)+` -M -S tailscale >/dev/null 2>&1; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if xbps-query -H 2>/dev/null | grep -Eq '(^|[[:space:]])tailscale([<>=~][^[:space:]]*)?([[:space:]]|$)'; then printf 'held=yes\n'; else printf 'held=no\n'; fi
if xbps-query --list-repolock-pkgs 2>/dev/null | grep -Eq '(^|[[:space:]])tailscale([<>=~][^[:space:]]*)?([[:space:]]|$)'; then printf 'repolocked=yes\n'; else printf 'repolocked=no\n'; fi
if test -d /etc/sv/tailscaled && ! test -L /etc/sv/tailscaled; then printf 'service_definition=yes\n'; else printf 'service_definition=no\n'; fi
if test -L /var/service/tailscaled && test "$(readlink -f /var/service/tailscaled)" = "$(readlink -f /etc/sv/tailscaled)"; then printf 'service_link=correct\n'; elif test -e /var/service/tailscaled || test -L /var/service/tailscaled; then printf 'service_link=conflict\n'; else printf 'service_link=absent\n'; fi
if test -d /etc/sv/tailscaled && ! test -L /etc/sv/tailscaled && sv status tailscaled 2>/dev/null | grep -Eq '^run:'; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState":"\([^"]*\)".*/backend=\1/p' | head -n 1; fi`)
	backend := lines["backend"]
	return facts.Tailscale{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceEnabled: lines["service_link"] == "correct", ServiceActive: lines["active"] == "yes", Connected: backend == "Running", BackendState: backend, RepositoryState: lines["repository"], ServiceDefinition: lines["service_definition"] == "yes", ServiceLinkState: lines["service_link"], PackageHeld: lines["held"] == "yes", PackageRepolocked: lines["repolocked"] == "yes"}
}

func inspectArchTailscale(ctx context.Context, tr transport.Transport, systemd bool) facts.Tailscale {
	lines := probeLines(ctx, tr, `
if pacman -Q tailscale >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if LC_ALL=C pacman -Si tailscale 2>/dev/null | awk -F ' *: *' 'function finish() { if (name != "") { if (name == "tailscale" && (repository == "core" || repository == "extra" || repository == "multilib")) count++; else invalid=1; name=""; repository="" } } $1 == "Repository" { finish(); repository=$2 } $1 == "Name" { name=$2 } END { finish(); exit !(count == 1 && !invalid) }'; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if systemctl is-enabled tailscaled.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active tailscaled.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState":"\([^"]*\)".*/backend=\1/p' | head -n 1; fi
`)
	backend := lines["backend"]
	return facts.Tailscale{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Connected: backend == "Running", BackendState: backend}
}

func inspectDevuanTailscale(ctx context.Context, tr transport.Transport) facts.Tailscale {
	lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' tailscale 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test ! -e /etc/apt/sources.list.d/tailscale.list; then
  printf 'repository=absent\n'
elif grep -Fqx 'deb https://pkgs.tailscale.com/stable/debian trixie main' /etc/apt/sources.list.d/tailscale.list 2>/dev/null && test "$(grep -Evc '^[[:space:]]*(#.*)?$|^deb https://pkgs\.tailscale\.com/stable/debian trixie main$' /etc/apt/sources.list.d/tailscale.list 2>/dev/null)" = 0 && test "$(sha256sum /usr/share/keyrings/tailscale-archive-keyring.gpg 2>/dev/null | awk '{print $1}')" = 3e03dacf222698c60b8e2f990b809ca1b3e104de127767864284e6c228f1fb39; then
  printf 'repository=managed\n'
else
  printf 'repository=unmanaged\n'
fi
candidate=$(LC_ALL=C apt-cache policy tailscale 2>/dev/null | awk '/^[[:space:]]*Candidate:/ {print $2; exit}')
if test -n "$candidate" && test "$candidate" != '(none)' && LC_ALL=C apt-cache madison tailscale 2>/dev/null | awk -v version="$candidate" '$3 == version { seen=1; if ($5 != "https://pkgs.tailscale.com/stable/debian" || $6 !~ /^trixie\//) bad=1; else good=1 } END { exit !(seen && good && !bad) }'; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if test ! -e /etc/init.d/tailscaled; then printf 'service_link=absent\n'; elif grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/init.d/tailscaled 2>/dev/null; then printf 'service_link=managed\n'; else printf 'service_link=conflict\n'; fi
enabled=no
for link in /etc/rc[2345].d/S??tailscaled; do
  test -L "$link" && test "$(readlink -f "$link")" = /etc/init.d/tailscaled || continue
  enabled=yes
  break
done
printf 'enabled=%s\n' "$enabled"
if test -x /etc/init.d/tailscaled && service tailscaled status >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState":"\\([^"]*\\)".*/backend=\\1/p' | head -n 1; fi`)
	return facts.Tailscale{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", Connected: lines["backend"] == "Running", BackendState: lines["backend"], RepositoryState: lines["repository"], ServiceDefinition: lines["service_link"] == "managed", ServiceLinkState: lines["service_link"]}
}

func inspectArtixTailscale(ctx context.Context, tr transport.Transport) facts.Tailscale {
	lines := probeLines(ctx, tr, `
if pacman -Q tailscale >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if pacman -Q tailscale tailscale-dinit >/dev/null 2>&1; then printf 'package_set=yes\n'; else printf 'package_set=no\n'; fi
if for package in tailscale tailscale-dinit; do LC_ALL=C pacman -Si "world/$package" 2>/dev/null | awk -F ' *: *' '$1 == "Repository" { found=($2 == "world") } END { exit !found }' || exit 1; done; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi
if test -f /etc/dinit.d/tailscaled && test -d /etc/dinit.d/boot.d; then printf 'service_definition=yes\n'; else printf 'service_definition=no\n'; fi
if test -L /etc/dinit.d/boot.d/tailscaled && test "$(readlink -f /etc/dinit.d/boot.d/tailscaled)" = /etc/dinit.d/tailscaled; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if dinitctl -s is-started tailscaled >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null | sed -n 's/.*"BackendState":"\\([^"]*\\)".*/backend=\\1/p' | head -n 1; fi`)
	return facts.Tailscale{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", Connected: lines["backend"] == "Running", BackendState: lines["backend"], RepositoryState: "artix-world", ServiceDefinition: lines["service_definition"] == "yes"}
}

func inspectUpdates(ctx context.Context, tr transport.Transport, init facts.InitSystem, packageManager string, os facts.OS) facts.AutomaticUpdates {
	if packageManager == "pacman" && os.Family == "arch" {
		return facts.AutomaticUpdates{ConfigState: "unsupported"}
	}
	if packageManager == "pacman" && os.Family == "artix" {
		return facts.AutomaticUpdates{ConfigState: "unsupported"}
	}
	if packageManager == "xbps" && os.Family == "void" {
		return facts.AutomaticUpdates{ConfigState: "unsupported"}
	}
	if packageManager == "apk" && os.Family == "alpine" {
		lines := probeLines(ctx, tr, `
if apk info -e apk-cron >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test -x /etc/init.d/crond; then printf 'service_exists=yes\n'; else printf 'service_exists=no\n'; fi
if test -x /etc/init.d/crond && rc-update show default 2>/dev/null | grep -Eq '^[[:space:]]*crond([[:space:]]|$)' && rc-service crond status >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
config=unmanaged
if test ! -e `+transport.ShellQuote(alpineBebopRepositoriesPath)+`; then
  config=absent
elif test "$(cat `+transport.ShellQuote(alpineBebopRepositoriesPath)+`)" = "$(printf '%s\\n' `+transport.ShellQuote(alpineBebopRepositories)+`)"; then
  config=managed
  for repository_file in /etc/apk/repositories /etc/apk/repositories.d/*.list; do
    test -f "$repository_file" || continue
    while IFS= read -r line || test -n "$line"; do
      case "$line" in ''|'#'*) continue;; esac
      case "$line" in
        'https://dl-cdn.alpinelinux.org/alpine/v3.24/main'|'https://dl-cdn.alpinelinux.org/alpine/v3.24/community'|'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 main'|'v2 https://dl-cdn.alpinelinux.org/alpine/v3.24 community'|'v2 @bebop-main https://dl-cdn.alpinelinux.org/alpine/v3.24 main'|'v2 @bebop-community https://dl-cdn.alpinelinux.org/alpine/v3.24 community') ;;
        *) config=unmanaged; break 2;;
      esac
    done < "$repository_file"
  done
fi
printf 'config=%s\n' "$config"
if apk policy apk-cron 2>/dev/null | grep -Fq 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main'; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi`)
		return facts.AutomaticUpdates{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceExists: lines["service_exists"] == "yes", Enabled: lines["enabled"] == "yes", ConfigState: lines["config"]}
	}
	if packageManager == "apt" && os.Family == "devuan" {
		lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' unattended-upgrades cron 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test -x /etc/init.d/cron && test -x /etc/cron.daily/apt-compat; then printf 'service_exists=yes\n'; else printf 'service_exists=no\n'; fi
enabled=no
for link in /etc/rc[2345].d/S??cron; do
  test -L "$link" && test "$(readlink -f "$link")" = /etc/init.d/cron || continue
  enabled=yes
  break
done
if test "$enabled" = yes && service cron status >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if test ! -e /etc/apt/apt.conf.d/52-bebop-auto-upgrades; then
  printf 'config=absent\n'
elif grep -Fqx '// Managed by Bebop. Manual edits may be replaced.' /etc/apt/apt.conf.d/52-bebop-auto-upgrades 2>/dev/null && grep -Fqx 'APT::Periodic::Update-Package-Lists "1";' /etc/apt/apt.conf.d/52-bebop-auto-upgrades 2>/dev/null && grep -Fqx 'APT::Periodic::Unattended-Upgrade "1";' /etc/apt/apt.conf.d/52-bebop-auto-upgrades 2>/dev/null && grep -Fqx '"o=Devuan,n=excalibur";' /etc/apt/apt.conf.d/52-bebop-auto-upgrades 2>/dev/null && grep -Fqx '"o=Devuan,n=excalibur-updates";' /etc/apt/apt.conf.d/52-bebop-auto-upgrades 2>/dev/null && grep -Fqx '"o=Devuan,n=excalibur-security";' /etc/apt/apt.conf.d/52-bebop-auto-upgrades 2>/dev/null; then
  printf 'config=managed\n'
else
  printf 'config=unmanaged\n'
fi
if for package in unattended-upgrades cron; do candidate=$(LC_ALL=C apt-cache policy "$package" 2>/dev/null | awk '/^[[:space:]]*Candidate:/ {print $2; exit}'); test -n "$candidate" && test "$candidate" != '(none)' && LC_ALL=C apt-cache madison "$package" 2>/dev/null | awk -v version="$candidate" '$3 == version { seen=1; if ($5 != "http://deb.devuan.org/merged" || $6 !~ /^excalibur(-updates|-security)?\//) bad=1; else good=1 } END { exit !(seen && good && !bad) }' || exit 1; done; then printf 'package_available=yes\n'; else printf 'package_available=no\n'; fi`)
		return facts.AutomaticUpdates{Installed: lines["installed"] == "yes", PackageAvailable: lines["package_available"] == "yes", ServiceExists: lines["service_exists"] == "yes", Enabled: lines["enabled"] == "yes", ConfigState: lines["config"]}
	}
	script := `
if dpkg-query -W -f='${db:Status-Status}' unattended-upgrades 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if apt-config dump 2>/dev/null | grep -Fqx 'APT::Periodic::Unattended-Upgrade "1";' && apt-config dump 2>/dev/null | grep -Fqx 'APT::Periodic::Update-Package-Lists "1";'; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
`
	if packageManager == "dnf5" {
		script = `
if rpm -q dnf5-plugin-automatic >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test ! -e /etc/dnf/automatic.conf; then printf 'config=absent\n'; elif grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/dnf/automatic.conf 2>/dev/null && grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/dnf/automatic.conf 2>/dev/null; then printf 'config=managed\n'; else printf 'config=unmanaged\n'; fi
if systemctl is-enabled dnf5-automatic.timer >/dev/null 2>&1 && systemctl is-active dnf5-automatic.timer >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
`
	}
	if packageManager == "dnf" {
		script = `
if rpm -q dnf-automatic >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test ! -e /etc/dnf/automatic.conf; then printf 'config=absent\n'; elif grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/dnf/automatic.conf 2>/dev/null && grep -Eq '^[[:space:]]*apply_updates[[:space:]]*=[[:space:]]*yes[[:space:]]*$' /etc/dnf/automatic.conf 2>/dev/null; then printf 'config=managed\n'; else printf 'config=unmanaged\n'; fi
if systemctl is-enabled dnf-automatic-install.timer >/dev/null 2>&1 && systemctl is-active dnf-automatic-install.timer >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
for timer in dnf-automatic.timer dnf-automatic-download.timer dnf-automatic-notifyonly.timer; do
  if systemctl is-enabled "$timer" >/dev/null 2>&1 || systemctl is-active "$timer" >/dev/null 2>&1; then printf 'conflicting_timers=yes\n'; fi
done
`
	}
	if packageManager == "zypper" {
		mode, ok := facts.OpenSUSEUpdatePolicy(os)
		if !ok {
			return facts.AutomaticUpdates{}
		}
		if mode == "tumbleweed" {
			script = `
if rpm -q os-update >/dev/null 2>&1; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if test ! -e /etc/os-update.conf; then printf 'config=absent\n'; elif grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/os-update.conf 2>/dev/null && grep -Eq '^[[:space:]]*UPDATE_CMD[[:space:]]*=[[:space:]]*dup[[:space:]]*$' /etc/os-update.conf 2>/dev/null && grep -Eq '^[[:space:]]*REBOOT_CMD[[:space:]]*=[[:space:]]*none[[:space:]]*$' /etc/os-update.conf 2>/dev/null; then printf 'config=managed\n'; else printf 'config=unmanaged\n'; fi
if systemctl is-enabled os-update.timer >/dev/null 2>&1 && systemctl is-active os-update.timer >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-enabled bebop-zypper-patch.timer >/dev/null 2>&1 || systemctl is-active bebop-zypper-patch.timer >/dev/null 2>&1; then printf 'conflicting_timers=yes\n'; fi
`
		} else {
			script = `
if test -e /etc/systemd/system/bebop-zypper-patch.service && test -e /etc/systemd/system/bebop-zypper-patch.timer; then
  if grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/systemd/system/bebop-zypper-patch.service 2>/dev/null && grep -Fqx '# Managed by Bebop. Manual edits may be replaced.' /etc/systemd/system/bebop-zypper-patch.timer 2>/dev/null; then printf 'installed=yes\n'; printf 'config=managed\n'; else printf 'config=unmanaged\n'; fi
else printf 'config=absent\n'; fi
if systemctl is-enabled bebop-zypper-patch.timer >/dev/null 2>&1 && systemctl is-active bebop-zypper-patch.timer >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-enabled os-update.timer >/dev/null 2>&1 || systemctl is-active os-update.timer >/dev/null 2>&1; then printf 'conflicting_timers=yes\n'; fi
`
		}
	}
	lines := probeLines(ctx, tr, script)
	available := false
	if packageManager == "zypper" {
		if mode, ok := facts.OpenSUSEUpdatePolicy(os); ok && mode == "tumbleweed" {
			repositories := mustProbe(ctx, tr, "zypper --non-interactive --no-refresh --xmlout lr -u 2>/dev/null || true")
			packages := mustProbe(ctx, tr, "zypper --non-interactive --no-refresh --xmlout search --details os-update 2>/dev/null || true")
			available = openSUSEPackagesAvailable(repositories, packages, "os-update")
		}
	}
	return facts.AutomaticUpdates{Installed: lines["installed"] == "yes", PackageAvailable: available, Enabled: lines["enabled"] == "yes", ConfigState: lines["config"], ConflictingTimers: lines["conflicting_timers"] == "yes"}
}

func inspectFirewall(ctx context.Context, tr transport.Transport) facts.Firewall {
	lines := probeLines(ctx, tr, `
if command -v ufw >/dev/null 2>&1; then printf 'ufw=yes\n'; else printf 'ufw=no\n'; fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -Fqx 'Status: active'; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if systemctl is-active nftables.service >/dev/null 2>&1 || systemctl is-active firewalld.service >/dev/null 2>&1; then printf 'other=yes\n'; else printf 'other=no\n'; fi
`)
	return facts.Firewall{UFWAvailable: lines["ufw"] == "yes", UFWActive: lines["active"] == "yes", OtherActive: lines["other"] == "yes"}
}

func inspectRootFilesystem(ctx context.Context, tr transport.Transport) facts.Filesystem {
	fields := strings.Fields(mustProbe(ctx, tr, "findmnt -n -o SOURCE,FSTYPE,SIZE,AVAIL,OPTIONS --target / 2>/dev/null || true"))
	if len(fields) == 5 {
		return facts.Filesystem{Source: fields[0], Type: fields[1], SizeKiB: parseSizeKiB(fields[2]), AvailableKiB: parseSizeKiB(fields[3]), ReadOnly: containsOption(fields[4], "ro")}
	}
	// Alpine's required findmnt utility may be absent during read-only
	// bootstrap. /proc/mounts still lets inspection fail closed for ephemeral
	// roots instead of mistaking a container overlay for a persistent host.
	fields = strings.Fields(mustProbe(ctx, tr, "awk '$2 == \"/\" { print $1, $3, $4; exit }' /proc/mounts 2>/dev/null || true"))
	if len(fields) == 3 {
		return facts.Filesystem{Source: fields[0], Type: fields[1], ReadOnly: containsOption(fields[2], "ro")}
	}
	return facts.Filesystem{}
}

func inspectMutationSafety(ctx context.Context, tr transport.Transport, root facts.Filesystem) (bool, string) {
	if root.ReadOnly {
		return true, "root filesystem is read-only"
	}
	if firstLine(mustProbe(ctx, tr, "if command -v transactional-update >/dev/null 2>&1; then printf yes; fi")) == "yes" {
		return true, "transactional-update is present; Bebop supports only conventional mutable hosts"
	}
	return false, ""
}

// inspectAlpineRootMode rejects installations whose root mutations are not
// ordinary persistent system-disk changes. lbu configuration is the Alpine
// persistence boundary for diskless/data modes; tmpfs and overlay roots catch
// the more direct run-from-RAM and ephemeral-root cases.
func inspectAlpineRootMode(ctx context.Context, tr transport.Transport, root facts.Filesystem) string {
	if root.ReadOnly {
		return "read-only"
	}
	switch root.Type {
	case "tmpfs":
		return "diskless"
	case "overlay", "overlayfs":
		return "ephemeral-overlay"
	}
	if firstLine(mustProbe(ctx, tr, "if test -e /etc/lbu/lbu.conf; then printf lbu-managed; fi")) == "lbu-managed" {
		return "diskless-or-data"
	}
	return "persistent"
}

// inspectVoidRootMode keeps Void support limited to ordinary persistent hosts.
// A container/chroot overlay is not evidence that runit or package changes
// will survive a reboot, so it fails before normal mutation planning.
func inspectVoidRootMode(root facts.Filesystem) string {
	if root.ReadOnly {
		return "read-only"
	}
	switch root.Type {
	case "tmpfs":
		return "ephemeral-tmpfs"
	case "overlay", "overlayfs":
		return "ephemeral-overlay"
	}
	return "persistent"
}

func containsOption(options, wanted string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == wanted {
			return true
		}
	}
	return false
}

func inspectUnconfiguredStorage(ctx context.Context, tr transport.Transport) []facts.StorageDevice {
	type blockDevice struct {
		Name        string        `json:"name"`
		Type        string        `json:"type"`
		Size        int64         `json:"size"`
		Mountpoints []*string     `json:"mountpoints"`
		Transport   string        `json:"tran"`
		Children    []blockDevice `json:"children"`
	}
	var response struct {
		Devices []blockDevice `json:"blockdevices"`
	}
	output := mustProbe(ctx, tr, "lsblk --json --bytes --output NAME,TYPE,SIZE,MOUNTPOINTS,TRAN 2>/dev/null || true")
	if json.Unmarshal([]byte(output), &response) != nil {
		return nil
	}
	result := make([]facts.StorageDevice, 0)
	var mounted func(blockDevice) bool
	mounted = func(device blockDevice) bool {
		for _, mountpoint := range device.Mountpoints {
			if mountpoint != nil && *mountpoint != "" {
				return true
			}
		}
		for _, child := range device.Children {
			if mounted(child) {
				return true
			}
		}
		return false
	}
	for _, device := range response.Devices {
		if device.Type == "disk" && !mounted(device) {
			result = append(result, facts.StorageDevice{Name: device.Name, SizeBytes: device.Size, Transport: device.Transport})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// inspectStorage consumes stable machine-readable util-linux output. It never
// probes decorative tables or follows a controller-provided device path. A
// missing lsblk/findmnt capability is explicit state; storage placement then
// blocks rather than guessing from a partial topology.
func inspectStorage(ctx context.Context, tr transport.Transport) facts.Storage {
	type rawDevice struct {
		Name        string      `json:"name"`
		Path        string      `json:"path"`
		Type        string      `json:"type"`
		Size        int64       `json:"size"`
		FSType      string      `json:"fstype"`
		Label       string      `json:"label"`
		UUID        string      `json:"uuid"`
		ReadOnly    bool        `json:"ro"`
		Removable   bool        `json:"rm"`
		Transport   string      `json:"tran"`
		Mountpoints []*string   `json:"mountpoints"`
		Children    []rawDevice `json:"children"`
	}
	var blocks struct {
		Devices []rawDevice `json:"blockdevices"`
	}
	blockOutput := mustProbe(ctx, tr, "lsblk --json --bytes --output NAME,PATH,TYPE,SIZE,FSTYPE,LABEL,UUID,RO,RM,TRAN,MOUNTPOINTS 2>/dev/null || true")
	blocksAvailable := json.Unmarshal([]byte(blockOutput), &blocks) == nil
	devices := make([]facts.BlockDevice, 0)
	byPath := map[string]facts.BlockDevice{}
	var flatten func(rawDevice)
	flatten = func(raw rawDevice) {
		device := facts.BlockDevice{Path: raw.Path, Name: raw.Name, Type: raw.Type, SizeBytes: raw.Size, Filesystem: raw.FSType, Label: raw.Label, UUID: raw.UUID, ReadOnly: raw.ReadOnly, Removable: raw.Removable, Transport: raw.Transport}
		for _, mount := range raw.Mountpoints {
			if mount != nil && *mount != "" {
				device.Mounts = append(device.Mounts, *mount)
			}
		}
		sort.Strings(device.Mounts)
		devices = append(devices, device)
		if device.Path != "" {
			byPath[device.Path] = device
		}
		for _, child := range raw.Children {
			flatten(child)
		}
	}
	if blocksAvailable {
		for _, device := range blocks.Devices {
			flatten(device)
		}
	}
	sort.Slice(devices, func(i, j int) bool { return devices[i].Path < devices[j].Path })

	type rawMount struct {
		Target   string     `json:"target"`
		Source   string     `json:"source"`
		FSType   string     `json:"fstype"`
		Options  string     `json:"options"`
		Size     int64      `json:"size"`
		Avail    int64      `json:"avail"`
		Children []rawMount `json:"children"`
	}
	var found struct {
		Filesystems []rawMount `json:"filesystems"`
	}
	mountOutput := mustProbe(ctx, tr, "findmnt --json --bytes --output TARGET,SOURCE,FSTYPE,OPTIONS,SIZE,AVAIL 2>/dev/null || true")
	if json.Unmarshal([]byte(mountOutput), &found) != nil {
		if !blocksAvailable {
			return facts.Storage{}
		}
		// lsblk still supplies UUID, filesystem type, and mounted target paths.
		// Capacity/options are unavailable, so policies that require a threshold
		// remain conservatively blocked by storage.Assess.
		fallback := make([]facts.StorageMount, 0)
		for _, device := range devices {
			for _, target := range device.Mounts {
				fallback = append(fallback, facts.StorageMount{Target: target, Source: device.Path, Filesystem: device.Filesystem, UUID: device.UUID, ReadOnly: device.ReadOnly})
			}
		}
		sort.Slice(fallback, func(i, j int) bool { return fallback[i].Target < fallback[j].Target })
		return facts.Storage{Available: true, Devices: devices, Mounts: fallback}
	}
	mounts := make([]facts.StorageMount, 0)
	var collect func(rawMount)
	collect = func(raw rawMount) {
		if raw.Target != "" {
			mount := facts.StorageMount{Target: raw.Target, Source: raw.Source, Filesystem: raw.FSType, Options: mountOptions(raw.Options), SizeBytes: raw.Size, AvailableBytes: raw.Avail, ReadOnly: mountReadOnly(raw.Options)}
			if block, ok := byPath[raw.Source]; ok {
				mount.UUID = block.UUID
				if mount.Filesystem == "" {
					mount.Filesystem = block.Filesystem
				}
				mount.ReadOnly = mount.ReadOnly || block.ReadOnly
			}
			mounts = append(mounts, mount)
		}
		for _, child := range raw.Children {
			collect(child)
		}
	}
	for _, mount := range found.Filesystems {
		collect(mount)
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Target < mounts[j].Target })
	// findmnt alone remains useful when lsblk is absent: it provides mounted
	// topology, filesystem type, read-only state, and capacity. UUID identity is
	// intentionally unavailable in that fallback, so UUID-declared storage
	// cannot become ready by guesswork.
	return facts.Storage{Available: true, Devices: devices, Mounts: mounts}
}

func mountReadOnly(options string) bool {
	for _, option := range strings.Split(options, ",") {
		if strings.TrimSpace(option) == "ro" {
			return true
		}
	}
	return false
}

func mountOptions(options string) []string {
	result := make([]string, 0)
	for _, option := range strings.Split(options, ",") {
		option = strings.TrimSpace(option)
		if option != "" {
			result = append(result, option)
		}
	}
	sort.Strings(result)
	return result
}

func inspectDataRoot(ctx context.Context, tr transport.Transport, root string) facts.Directory {
	directory := facts.Directory{Path: root}
	output := mustProbe(ctx, tr, "if test -d "+transport.ShellQuote(root)+"; then stat -c '%a %u %g' -- "+transport.ShellQuote(root)+"; fi")
	fields := strings.Fields(output)
	if len(fields) != 3 {
		return directory
	}
	directory.Exists = true
	directory.Mode = fields[0]
	directory.UID, _ = strconv.Atoi(fields[1])
	directory.GID, _ = strconv.Atoi(fields[2])
	directory.Writable = mustProbe(ctx, tr, "if test -w "+transport.ShellQuote(root)+"; then printf yes; else printf no; fi") == "yes"
	return directory
}

func probeLines(ctx context.Context, tr transport.Transport, script string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(mustProbe(ctx, tr, script), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), "=")
		if found {
			values[key] = value
		}
	}
	return values
}

func firstLine(value string) string {
	if line, _, found := strings.Cut(value, "\n"); found {
		return strings.TrimSpace(line)
	}
	return strings.TrimSpace(value)
}

func parseMemory(value string) int64 {
	number, _ := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	return number
}

func parseSizeKiB(value string) int64 {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	multiplier := int64(1)
	switch value[len(value)-1] {
	case 'K', 'k':
		value = value[:len(value)-1]
	case 'M', 'm':
		multiplier, value = 1024, value[:len(value)-1]
	case 'G', 'g':
		multiplier, value = 1024*1024, value[:len(value)-1]
	case 'T', 't':
		multiplier, value = 1024*1024*1024, value[:len(value)-1]
	}
	parsed, _ := strconv.ParseFloat(value, 64)
	return int64(parsed * float64(multiplier))
}
