// Package inspect gathers normalized facts through a transport. It is strictly
// read-only: every request is a probe, never a package, service, or file change.
package inspect

import (
	"context"
	"encoding/json"
	"fmt"
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
	f := facts.HostFacts{Target: target.String(), OS: osFacts, PackageManager: "unknown", DataRoot: facts.Directory{Path: dataRoot}}
	f.Hostname = firstLine(mustProbe(ctx, tr, "hostname"))
	f.MachineID = firstLine(mustProbe(ctx, tr, "cat /etc/machine-id 2>/dev/null || true"))
	rawArchitecture := firstLine(mustProbe(ctx, tr, "uname -m"))
	f.Architecture, f.ArchitectureKnown = facts.NormalizeArchitecture(rawArchitecture)
	f.Kernel = firstLine(mustProbe(ctx, tr, "uname -r"))
	f.EffectiveUser = firstLine(mustProbe(ctx, tr, "id -un"))
	f.SudoAvailable = firstLine(mustProbe(ctx, tr, "if test \"$(id -u)\" -eq 0 || (command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1); then printf yes; else printf no; fi")) == "yes"
	f.Systemd = firstLine(mustProbe(ctx, tr, "if command -v systemctl >/dev/null 2>&1 && test -d /run/systemd/system; then printf yes; else printf no; fi")) == "yes"
	if firstLine(mustProbe(ctx, tr, "if command -v apt-get >/dev/null 2>&1 && command -v dpkg-query >/dev/null 2>&1; then printf apt; fi")) == "apt" {
		f.PackageManager = "apt"
	}
	if f.Systemd {
		f.InitSystem = "systemd"
	} else {
		f.InitSystem = "unknown"
	}
	f.SSH = inspectSSH(ctx, tr)
	f.Docker = inspectDocker(ctx, tr, f.Systemd)
	deployments, err := services.ResolveAll(cfg)
	if err != nil {
		return facts.HostFacts{}, err
	}
	f.Services = inspectServices(ctx, tr, dataRoot, deployments, f.Docker.Responsive)
	f.Tailscale = inspectTailscale(ctx, tr, f.Systemd)
	f.AutomaticUpdates = inspectUpdates(ctx, tr)
	f.Firewall = inspectFirewall(ctx, tr)
	f.MemoryKiB = parseMemory(mustProbe(ctx, tr, "awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true"))
	f.RootFilesystem = inspectRootFilesystem(ctx, tr)
	f.UnconfiguredStorage = inspectUnconfiguredStorage(ctx, tr)
	f.Storage = inspectStorage(ctx, tr)
	for _, assessment := range storagepolicy.AssessAll(cfg.Storage, f.Storage) {
		f.Storage.Policy = append(f.Storage.Policy, facts.StoragePolicy{Name: assessment.Resource.Name, State: string(assessment.State)})
	}
	f.DataRoot = inspectDataRoot(ctx, tr, dataRoot)
	return f, nil
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

func inspectSSH(ctx context.Context, tr transport.Transport) facts.SSH {
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

func inspectDocker(ctx context.Context, tr transport.Transport, systemd bool) facts.Docker {
	lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' docker.io 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
if { test "$(id -u)" -eq 0 && env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root docker --context default compose version >/dev/null 2>&1; }; then printf 'compose=yes\n'; else printf 'compose=no\n'; fi
if apt-cache show docker-compose-plugin >/dev/null 2>&1; then printf 'compose_package=docker-compose-plugin\n'; elif apt-cache show docker-compose-v2 >/dev/null 2>&1; then printf 'compose_package=docker-compose-v2\n'; else printf 'compose_package=\n'; fi
`)
	return facts.Docker{Installed: lines["installed"] == "yes", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Responsive: lines["responsive"] == "yes", ComposeAvailable: lines["compose"] == "yes", ComposePackageAvailable: lines["compose_package"]}
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
  digest=$(cd -- "$current" && find . -type f ! -path './` + services.SecretEnvName + `' ! -path './` + services.SecretFingerprintName + `' -printf '%P\n' | LC_ALL=C sort | while IFS= read -r file; do
    test -n "$file" || continue
    mode=$(stat -c '%a' -- "$file")
    checksum=$(sha256sum -- "$file" | awk '{print $1}')
    printf '%s\t%s\t%s\n' "$mode" "$checksum" "$file"
  done | sha256sum | awk '{print $1}')
  printf 'deployment=yes\n'
  printf 'digest=%s\n' "$digest"
  if test -f "$current"/` + transport.ShellQuote(services.SecretFingerprintName) + `; then tr -d '\n' < "$current"/` + transport.ShellQuote(services.SecretFingerprintName) + ` | sed 's/^/secret_fingerprint=/'; else printf 'secret_fingerprint=\n'; fi
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

func inspectTailscale(ctx context.Context, tr transport.Transport, systemd bool) facts.Tailscale {
	lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' tailscale 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled tailscaled.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active tailscaled.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
`)
	status := struct {
		BackendState string `json:"BackendState"`
		Self         *struct {
			Online bool `json:"Online"`
		} `json:"Self"`
	}{}
	_ = json.Unmarshal([]byte(mustProbe(ctx, tr, "if command -v tailscale >/dev/null 2>&1; then tailscale status --json 2>/dev/null || true; fi")), &status)
	connected := status.BackendState == "Running" && status.Self != nil && status.Self.Online
	return facts.Tailscale{Installed: lines["installed"] == "yes", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Connected: connected, BackendState: status.BackendState}
}

func inspectUpdates(ctx context.Context, tr transport.Transport) facts.AutomaticUpdates {
	lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' unattended-upgrades 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if apt-config dump 2>/dev/null | grep -Fqx 'APT::Periodic::Unattended-Upgrade "1";' && apt-config dump 2>/dev/null | grep -Fqx 'APT::Periodic::Update-Package-Lists "1";'; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
`)
	return facts.AutomaticUpdates{Installed: lines["installed"] == "yes", Enabled: lines["enabled"] == "yes"}
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
	fields := strings.Fields(mustProbe(ctx, tr, "findmnt -n -o SOURCE,FSTYPE,SIZE,AVAIL --target / 2>/dev/null || true"))
	if len(fields) != 4 {
		return facts.Filesystem{}
	}
	return facts.Filesystem{Source: fields[0], Type: fields[1], SizeKiB: parseSizeKiB(fields[2]), AvailableKiB: parseSizeKiB(fields[3])}
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
	blockOutput := mustProbe(ctx, tr, "lsblk --json --bytes --output NAME,PATH,TYPE,SIZE,FSTYPE,UUID,RO,RM,TRAN,MOUNTPOINTS 2>/dev/null || true")
	if json.Unmarshal([]byte(blockOutput), &blocks) != nil {
		return facts.Storage{}
	}
	devices := make([]facts.BlockDevice, 0)
	byPath := map[string]facts.BlockDevice{}
	var flatten func(rawDevice)
	flatten = func(raw rawDevice) {
		device := facts.BlockDevice{Path: raw.Path, Name: raw.Name, Type: raw.Type, SizeBytes: raw.Size, Filesystem: raw.FSType, UUID: raw.UUID, ReadOnly: raw.ReadOnly, Removable: raw.Removable, Transport: raw.Transport}
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
	for _, device := range blocks.Devices {
		flatten(device)
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
		return facts.Storage{Devices: devices}
	}
	mounts := make([]facts.StorageMount, 0)
	var collect func(rawMount)
	collect = func(raw rawMount) {
		if raw.Target != "" {
			mount := facts.StorageMount{Target: raw.Target, Source: raw.Source, Filesystem: raw.FSType, SizeBytes: raw.Size, AvailableBytes: raw.Avail, ReadOnly: mountReadOnly(raw.Options)}
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
