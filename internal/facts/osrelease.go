package facts

import (
	"bufio"
	"strings"
)

// ParseOSRelease parses the shell-compatible but deliberately small os-release
// format. It accepts quoted values and ignores comments/blank lines.
func ParseOSRelease(contents string) (OS, error) {
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(contents))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return OS{}, err
	}
	id := strings.ToLower(values["ID"])
	os := OS{ID: id, Name: values["NAME"], VersionID: values["VERSION_ID"], BuildID: strings.ToLower(values["BUILD_ID"]), VersionCodename: strings.ToLower(values["VERSION_CODENAME"]), PlatformID: strings.ToLower(values["PLATFORM_ID"]), Family: platformFamily(id)}
	if id == "raspbian" {
		os.Name = "Raspberry Pi OS"
	}
	// PlatformPolicyFor is the sole release/identity allow-list. It uses only
	// exact os-release fields and intentionally ignores ID_LIKE.
	_, os.Supported = PlatformPolicyFor(os)
	return os, nil
}

func isAlpine324(version string) bool {
	return strings.HasPrefix(version, "3.24.") && numericVersionTriplet(version)
}

func numericVersionTriplet(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, rune := range part {
			if rune < '0' || rune > '9' {
				return false
			}
		}
	}
	return true
}

// RequiredPackageTools is the small platform capability model used by
// inspection and planning. RPM and Debian-family managers have a paired
// installed-package database tool; Pacman itself provides Arch's reviewed
// package-query capability and therefore has an empty database value.
func RequiredPackageTools(os OS) (manager, database string, ok bool) {
	if policy, supported := PlatformPolicyFor(os); supported {
		return policy.PackageManager, policy.PackageDatabase, true
	}
	family := os.Family
	if family == "" || family == "unsupported" {
		family = platformFamily(os.ID)
	}
	return packageToolsForFamily(family, os)
}

func packageToolsForFamily(family string, os OS) (manager, database string, ok bool) {
	switch family {
	case "debian", "ubuntu", "raspberry-pi-os", "devuan":
		return "apt", "dpkg", true
	case "fedora":
		return "dnf5", "rpm", true
	case "enterprise-linux":
		return "dnf", "rpm", true
	case "opensuse":
		return "zypper", "rpm", true
	case "arch", "artix":
		return "pacman", "", true
	case "alpine":
		return "apk", "", true
	case "void":
		return "xbps", "", true
	default:
		// Hand-constructed facts in callers predating the family field retain
		// the original apt contract. Real inspection always supplies an OS ID.
		if os.Supported && os.ID == "" {
			return "apt", "dpkg", true
		}
		return "", "", false
	}
}

// OpenSUSEUpdatePolicy identifies the fixed-release and rolling update
// contracts. It is deliberately based on exact supported identities.
func OpenSUSEUpdatePolicy(os OS) (string, bool) {
	if !os.IsSupported() || os.Family != "opensuse" {
		return "", false
	}
	switch os.ID {
	case "opensuse-leap":
		return "leap", true
	case "opensuse-tumbleweed":
		return "tumbleweed", true
	}
	return "", false
}

// OpenSUSETailscaleRepositoryPolicy returns the reviewed repository path for
// an exact openSUSE target. Callers must not derive this from ID_LIKE.
func OpenSUSETailscaleRepositoryPolicy(os OS) (string, bool) {
	mode, ok := OpenSUSEUpdatePolicy(os)
	if !ok {
		return "", false
	}
	if mode == "leap" {
		return "stable/opensuse/leap/16.0", true
	}
	return "stable/opensuse/tumbleweed", true
}

// EnterpriseLinuxMajor returns the reviewed ABI major for a supported EL
// target. It intentionally does not infer support from ID_LIKE or VERSION_ID
// prefixes; callers must first work with an explicitly supported OS fact.
func EnterpriseLinuxMajor(os OS) (string, bool) {
	if !os.IsSupported() || os.Family != "enterprise-linux" {
		return "", false
	}
	switch os.ID {
	case "rocky", "almalinux":
		if os.VersionID == "9.8" {
			return "9", true
		}
		if os.VersionID == "10.2" {
			return "10", true
		}
	case "centos":
		if os.VersionID == "9" {
			return "9", true
		}
		if os.VersionID == "10" {
			return "10", true
		}
	}
	return "", false
}

// DockerCERepositoryPolicy identifies the fixed Docker RPM repository family
// selected by Bebop's explicit Enterprise Linux support policy.
func DockerCERepositoryPolicy(os OS) (family, major string, ok bool) {
	major, ok = EnterpriseLinuxMajor(os)
	if !ok {
		return "", "", false
	}
	if os.ID == "centos" {
		return "centos", major, true
	}
	return "rhel", major, true
}

// TailscaleRPMRepositoryPolicy identifies the fixed Tailscale RPM repository
// family for an explicitly supported Enterprise Linux target.
func TailscaleRPMRepositoryPolicy(os OS) (family, major string, ok bool) {
	return DockerCERepositoryPolicy(os)
}

func PackageToolsAvailable(os OS, manager, database string) bool {
	requiredManager, requiredDatabase, ok := RequiredPackageTools(os)
	return ok && manager == requiredManager && database == requiredDatabase
}

func NormalizeSELinuxMode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "enforcing", "permissive", "disabled":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "unavailable"
	}
}

func NormalizeArchitecture(raw string) (string, bool) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "x86_64", "amd64":
		return "amd64", true
	case "aarch64", "arm64":
		return "arm64", true
	default:
		return strings.TrimSpace(raw), false
	}
}

// NormalizeVoidArchitecture decodes Void's native XBPS architecture token.
// Libc stays separate from CPU architecture so it can be planner-relevant
// without becoming target identity or leaking XBPS compound values elsewhere.
func NormalizeVoidArchitecture(raw string) (architecture, libc string, ok bool) {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "x86_64":
		return "amd64", "glibc", true
	case "x86_64-musl":
		return "amd64", "musl", true
	case "aarch64":
		return "arm64", "glibc", true
	case "aarch64-musl":
		return "arm64", "musl", true
	default:
		return "", "", false
	}
}

// VoidRepository returns the reviewed official repository for an exact Void
// architecture/libc pair. Aarch64 uses Void's architecture-specific canonical
// endpoint, whose repository data carries both glibc and musl architectures.
func VoidRepository(architecture, libc string) (string, bool) {
	switch architecture + "/" + libc {
	case "amd64/glibc":
		return "https://repo-default.voidlinux.org/current", true
	case "amd64/musl":
		return "https://repo-default.voidlinux.org/current/musl", true
	case "arm64/glibc":
		return "https://repo-default.voidlinux.org/current/aarch64", true
	case "arm64/musl":
		return "https://repo-default.voidlinux.org/current/aarch64", true
	default:
		return "", false
	}
}

func VoidLibcSupported(os OS, libc string) bool {
	return os.ID == "void" && LibcSupported(os, libc)
}
