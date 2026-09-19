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
	os := OS{ID: id, Name: values["NAME"], VersionID: values["VERSION_ID"], BuildID: strings.ToLower(values["BUILD_ID"]), VersionCodename: strings.ToLower(values["VERSION_CODENAME"]), PlatformID: strings.ToLower(values["PLATFORM_ID"])}
	switch id {
	case "debian":
		os.Family, os.Supported = "debian", true
	case "ubuntu":
		os.Family, os.Supported = "ubuntu", true
	case "raspbian":
		os.Family, os.Supported = "raspberry-pi-os", true
		os.Name = "Raspberry Pi OS"
	case "fedora":
		os.Family = "fedora"
		// Fedora is deliberately version-gated. A new Fedora release is not
		// supported until its package/runtime contract has been reviewed.
		os.Supported = os.VersionID == "43" || os.VersionID == "44"
	case "rocky":
		os.Family = "enterprise-linux"
		os.Supported = os.VersionID == "9.8" || os.VersionID == "10.2"
	case "almalinux":
		os.Family = "enterprise-linux"
		os.Supported = os.VersionID == "9.8" || os.VersionID == "10.2"
	case "centos":
		os.Family = "enterprise-linux"
		// CentOS Linux also used ID=centos. Require both the Stream name and
		// the matching machine-readable EL platform identity.
		os.Supported = (os.VersionID == "9" && os.Name == "CentOS Stream" && os.PlatformID == "platform:el9") || (os.VersionID == "10" && os.Name == "CentOS Stream" && os.PlatformID == "platform:el10")
	case "opensuse-leap":
		os.Family = "opensuse"
		os.Supported = os.VersionID == "16.0"
	case "opensuse-tumbleweed":
		// Tumbleweed is rolling. Its snapshot date is useful display metadata,
		// not a release gate; exact ID remains the support boundary.
		os.Family, os.Supported = "opensuse", true
	case "arch":
		// Arch is rolling, but only the official rolling distribution is
		// reviewed. ID_LIKE and image-version metadata are deliberately not
		// support signals.
		os.Family = "arch"
		os.Supported = os.BuildID == "rolling"
	default:
		os.Family = "unsupported"
	}
	return os, nil
}

// RequiredPackageTools is the small platform capability model used by
// inspection and planning. A manager value is reported only when its paired
// installed-package database tool is also available.
func RequiredPackageTools(os OS) (manager, database string, ok bool) {
	family := os.Family
	if family == "" {
		switch os.ID {
		case "debian":
			family = "debian"
		case "ubuntu":
			family = "ubuntu"
		case "raspbian":
			family = "raspberry-pi-os"
		case "fedora":
			family = "fedora"
		case "rocky", "almalinux", "centos":
			family = "enterprise-linux"
		case "arch":
			family = "arch"
		}
	}
	switch family {
	case "debian", "ubuntu", "raspberry-pi-os":
		return "apt", "dpkg", true
	case "fedora":
		return "dnf5", "rpm", true
	case "enterprise-linux":
		return "dnf", "rpm", true
	case "opensuse":
		return "zypper", "rpm", true
	case "arch":
		return "pacman", "", true
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
