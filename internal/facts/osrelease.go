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
	default:
		os.Family = "unsupported"
	}
	return os, nil
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
