// Package inspect gathers normalized facts through a transport. It is strictly
// read-only: every request is a probe, never a package, service, or file change.
package inspect

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

type Inspector struct{}

func (Inspector) Inspect(ctx context.Context, tr transport.Transport, target target.Target, dataRoot string) (facts.HostFacts, error) {
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
	f := facts.HostFacts{Target: target.String(), OS: osFacts, PackageManager: "apt", DataRoot: facts.Directory{Path: dataRoot}}
	f.Hostname = firstLine(mustProbe(ctx, tr, "hostname"))
	rawArchitecture := firstLine(mustProbe(ctx, tr, "uname -m"))
	f.Architecture, f.ArchitectureKnown = facts.NormalizeArchitecture(rawArchitecture)
	f.Kernel = firstLine(mustProbe(ctx, tr, "uname -r"))
	f.EffectiveUser = firstLine(mustProbe(ctx, tr, "id -un"))
	f.SudoAvailable = firstLine(mustProbe(ctx, tr, "if test \"$(id -u)\" -eq 0 || (command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1); then printf yes; else printf no; fi")) == "yes"
	f.Systemd = firstLine(mustProbe(ctx, tr, "if command -v systemctl >/dev/null 2>&1 && test -d /run/systemd/system; then printf yes; else printf no; fi")) == "yes"
	if f.Systemd {
		f.InitSystem = "systemd"
	} else {
		f.InitSystem = "unknown"
	}
	f.SSH = inspectSSH(ctx, tr)
	f.Docker = inspectDocker(ctx, tr, f.Systemd)
	f.Tailscale = inspectTailscale(ctx, tr, f.Systemd)
	f.AutomaticUpdates = inspectUpdates(ctx, tr)
	f.Firewall = inspectFirewall(ctx, tr)
	f.MemoryKiB = parseMemory(mustProbe(ctx, tr, "awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || true"))
	f.RootFilesystem = inspectRootFilesystem(ctx, tr)
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
home=$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6)
if test -n "$home" && test -s "$home/.ssh/authorized_keys"; then printf 'keys=yes\n'; else printf 'keys=no\n'; fi
`)
	return facts.SSH{Installed: lines["installed"] == "yes", Service: lines["service"], ServiceEnabled: lines["enabled"] == "yes", ServiceActive: lines["active"] == "yes", ConfigValid: lines["valid"] == "yes", AuthorizedKeysPresent: lines["keys"] == "yes", BebopDropIn: mustProbe(ctx, tr, "if test -r /etc/ssh/sshd_config.d/99-bebop.conf; then cat /etc/ssh/sshd_config.d/99-bebop.conf; fi")}
}

func inspectDocker(ctx context.Context, tr transport.Transport, systemd bool) facts.Docker {
	lines := probeLines(ctx, tr, `
if dpkg-query -W -f='${db:Status-Status}' docker.io 2>/dev/null | grep -qx installed; then printf 'installed=yes\n'; else printf 'installed=no\n'; fi
if systemctl is-enabled docker.service >/dev/null 2>&1; then printf 'enabled=yes\n'; else printf 'enabled=no\n'; fi
if systemctl is-active docker.service >/dev/null 2>&1; then printf 'active=yes\n'; else printf 'active=no\n'; fi
if { test "$(id -u)" -eq 0 && docker info >/dev/null 2>&1; } || { test "$(id -u)" -ne 0 && sudo -n docker info >/dev/null 2>&1; }; then printf 'responsive=yes\n'; else printf 'responsive=no\n'; fi
`)
	return facts.Docker{Installed: lines["installed"] == "yes", ServiceEnabled: systemd && lines["enabled"] == "yes", ServiceActive: systemd && lines["active"] == "yes", Responsive: lines["responsive"] == "yes"}
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

func inspectDataRoot(ctx context.Context, tr transport.Transport, root string) facts.Directory {
	directory := facts.Directory{Path: root}
	output := mustProbe(ctx, tr, "if test -d -- "+transport.ShellQuote(root)+"; then stat -c '%a %u %g' -- "+transport.ShellQuote(root)+"; fi")
	fields := strings.Fields(output)
	if len(fields) != 3 {
		return directory
	}
	directory.Exists = true
	directory.Mode = fields[0]
	directory.UID, _ = strconv.Atoi(fields[1])
	directory.GID, _ = strconv.Atoi(fields[2])
	directory.Writable = mustProbe(ctx, tr, "if test -w -- "+transport.ShellQuote(root)+"; then printf yes; else printf no; fi") == "yes"
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
