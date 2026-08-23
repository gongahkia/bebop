// Package config loads Bebop's strict, versioned declarative configuration.
package config

import (
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/pelletier/go-toml/v2"
)

const CurrentVersion = 1
const DefaultDataRoot = "/srv/bebop"

type Config struct {
	Version  int      `toml:"version" json:"version"`
	Server   Server   `toml:"server" json:"server"`
	Features Features `toml:"features" json:"features"`
	Network  Network  `toml:"network" json:"network"`
	Storage  Storage  `toml:"storage" json:"storage"`
}

type Server struct {
	Name string `toml:"name" json:"name"`
}
type Features struct {
	AutomaticUpdates bool `toml:"automatic_updates" json:"automatic_updates"`
	SSHHardening     bool `toml:"ssh_hardening" json:"ssh_hardening"`
	Docker           bool `toml:"docker" json:"docker"`
	Tailscale        bool `toml:"tailscale" json:"tailscale"`
}
type Network struct {
	Firewall string `toml:"firewall" json:"firewall"`
}
type Storage struct {
	DataRoot string `toml:"data_root" json:"data_root"`
}

type rawConfig struct {
	Version int `toml:"version"`
	Server  struct {
		Name *string `toml:"name"`
	} `toml:"server"`
	Features struct {
		AutomaticUpdates *bool `toml:"automatic_updates"`
		SSHHardening     *bool `toml:"ssh_hardening"`
		Docker           *bool `toml:"docker"`
		Tailscale        *bool `toml:"tailscale"`
	} `toml:"features"`
	Network struct {
		Firewall *string `toml:"firewall"`
	} `toml:"network"`
	Storage struct {
		DataRoot *string `toml:"data_root"`
	} `toml:"storage"`
}

func Defaults() Config {
	return Config{Version: CurrentVersion, Server: Server{Name: "home"}, Features: Features{AutomaticUpdates: true, SSHHardening: true, Docker: true, Tailscale: true}, Network: Network{Firewall: "disabled"}, Storage: Storage{DataRoot: DefaultDataRoot}}
}

func LoadFile(filename string) (Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Config{}, errs.New(errs.ConfigInvalid, "cannot read configuration", err)
	}
	defer file.Close()
	return Decode(file)
}

func Decode(reader io.Reader) (Config, error) {
	var raw rawConfig
	decoder := toml.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, errs.New(errs.ConfigInvalid, "invalid bebop.toml", err)
	}
	config := Defaults()
	config.Version = raw.Version
	if raw.Server.Name != nil {
		config.Server.Name = *raw.Server.Name
	}
	if raw.Features.AutomaticUpdates != nil {
		config.Features.AutomaticUpdates = *raw.Features.AutomaticUpdates
	}
	if raw.Features.SSHHardening != nil {
		config.Features.SSHHardening = *raw.Features.SSHHardening
	}
	if raw.Features.Docker != nil {
		config.Features.Docker = *raw.Features.Docker
	}
	if raw.Features.Tailscale != nil {
		config.Features.Tailscale = *raw.Features.Tailscale
	}
	if raw.Network.Firewall != nil {
		config.Network.Firewall = *raw.Network.Firewall
	}
	if raw.Storage.DataRoot != nil {
		config.Storage.DataRoot = *raw.Storage.DataRoot
	}
	if err := Validate(config); err != nil {
		return Config{}, err
	}
	return config, nil
}

var namePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)

func Validate(config Config) error {
	if config.Version != CurrentVersion {
		return errs.New(errs.ConfigInvalid, fmt.Sprintf("unsupported configuration version %d (expected %d)", config.Version, CurrentVersion), nil)
	}
	if !namePattern.MatchString(config.Server.Name) {
		return errs.New(errs.ConfigInvalid, "server.name must be 1-63 letters, numbers, dots, underscores, or hyphens", nil)
	}
	if config.Network.Firewall != "disabled" {
		return errs.New(errs.ConfigInvalid, "network.firewall currently supports only \"disabled\"; Bebop M0 never configures firewalls", nil)
	}
	if err := ValidateDataRoot(config.Storage.DataRoot); err != nil {
		return errs.New(errs.ConfigInvalid, err.Error(), nil)
	}
	return nil
}

func ValidateDataRoot(root string) error {
	if root == "" || !strings.HasPrefix(root, "/") {
		return fmt.Errorf("storage.data_root must be an absolute path")
	}
	if root == "/" || path.Clean(root) != root || strings.ContainsRune(root, '\x00') {
		return fmt.Errorf("storage.data_root must be a clean absolute path other than /")
	}
	if len(root) > 240 {
		return fmt.Errorf("storage.data_root is too long")
	}
	return nil
}

func Starter() string {
	config := Defaults()
	// The fixed template is intentionally timestamp-free and reproducible.
	return fmt.Sprintf(`version = %d

[server]
name = %q

[features]
automatic_updates = %t
ssh_hardening = %t
docker = %t
tailscale = %t

[network]
firewall = %q

[storage]
data_root = %q
`, config.Version, config.Server.Name, config.Features.AutomaticUpdates, config.Features.SSHHardening, config.Features.Docker, config.Features.Tailscale, config.Network.Firewall, config.Storage.DataRoot)
}
