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
	os := OS{ID: id, Name: values["NAME"], VersionID: values["VERSION_ID"], VersionCodename: strings.ToLower(values["VERSION_CODENAME"])}
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
		}
	}
	switch family {
	case "debian", "ubuntu", "raspberry-pi-os":
		return "apt", "dpkg", true
	case "fedora":
		return "dnf5", "rpm", true
	default:
		// Hand-constructed facts in callers predating the family field retain
		// the original apt contract. Real inspection always supplies an OS ID.
		if os.Supported && os.ID == "" {
			return "apt", "dpkg", true
		}
		return "", "", false
	}
}

func PackageToolsAvailable(os OS, manager string) bool {
	requiredManager, _, ok := RequiredPackageTools(os)
	return ok && manager == requiredManager
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
