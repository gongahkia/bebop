// Package inventory owns Bebop's local, declarative host inventory.
package inventory

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/pelletier/go-toml/v2"
)

const CurrentVersion = 1
const DefaultPath = "bebop.hosts.toml"

// Host is metadata kept on the controller. It intentionally has no credential
// fields: SSH authentication remains exclusively under the user's OpenSSH
// configuration.
type Host struct {
	Target string `toml:"target" json:"target"`
	Config string `toml:"config,omitempty" json:"config,omitempty"`
}

// Inventory is versioned so it can be checked into source control and evolved
// without guessing how to interpret old files.
type Inventory struct {
	Version int             `toml:"version" json:"version"`
	Hosts   map[string]Host `toml:"hosts" json:"hosts"`
}

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)

func Empty() Inventory { return Inventory{Version: CurrentVersion, Hosts: map[string]Host{}} }

func LoadFile(filename string) (Inventory, error) {
	file, err := os.Open(filename)
	if err != nil {
		return Inventory{}, errs.New(errs.InventoryInvalid, "cannot read host inventory", err)
	}
	defer file.Close()
	return Decode(file)
}

// LoadOrEmpty makes first-time host registration ergonomic while keeping the
// stricter LoadFile contract available to callers that require an inventory.
func LoadOrEmpty(filename string) (Inventory, error) {
	result, err := LoadFile(filename)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return Empty(), nil
	}
	return result, err
}

func Decode(reader io.Reader) (Inventory, error) {
	var result Inventory
	decoder := toml.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return Inventory{}, errs.New(errs.InventoryInvalid, "invalid host inventory", err)
	}
	if result.Hosts == nil {
		result.Hosts = map[string]Host{}
	}
	if err := Validate(result); err != nil {
		return Inventory{}, err
	}
	return result, nil
}

func Validate(result Inventory) error {
	if result.Version != CurrentVersion {
		return errs.New(errs.InventoryInvalid, fmt.Sprintf("unsupported inventory version %d (expected %d)", result.Version, CurrentVersion), nil)
	}
	seenTargets := map[string]string{}
	for alias, host := range result.Hosts {
		if err := ValidateAlias(alias); err != nil {
			return err
		}
		if _, err := target.Parse(host.Target); err != nil {
			return errs.New(errs.InventoryInvalid, "invalid target for host "+alias, err)
		}
		if previous, exists := seenTargets[host.Target]; exists {
			return errs.New(errs.InventoryInvalid, fmt.Sprintf("hosts %q and %q use the same target", previous, alias), nil)
		}
		seenTargets[host.Target] = alias
		if err := ValidateConfigPath(host.Config); err != nil {
			return errs.New(errs.InventoryInvalid, "invalid config for host "+alias+": "+err.Error(), nil)
		}
	}
	return nil
}

func ValidateAlias(alias string) error {
	if alias == "local" || !aliasPattern.MatchString(alias) {
		return errs.New(errs.InventoryInvalid, "host alias must be 1-63 letters, numbers, dots, underscores, or hyphens and cannot be local", nil)
	}
	return nil
}

// ValidateConfigPath keeps inventory references portable and prevents a
// checked-in inventory from escaping its own directory through ../ segments.
// Controller paths are deliberately distinct from remote POSIX paths.
func ValidateConfigPath(configPath string) error {
	if configPath == "" {
		return nil
	}
	if strings.ContainsRune(configPath, '\x00') || filepath.IsAbs(configPath) {
		return fmt.Errorf("config path must be a non-absolute relative path")
	}
	for _, character := range configPath {
		if character < 0x20 || character == 0x7f {
			return fmt.Errorf("config path must not contain control characters")
		}
	}
	cleaned := filepath.Clean(filepath.FromSlash(configPath))
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) {
		return fmt.Errorf("config path must stay within the inventory directory")
	}
	for _, part := range strings.FieldsFunc(cleaned, func(r rune) bool { return r == '/' || r == '\\' }) {
		if part == ".." {
			return fmt.Errorf("config path must stay within the inventory directory")
		}
	}
	return nil
}

func ConfigPath(inventoryPath string, host Host) string {
	if host.Config == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(inventoryPath), filepath.FromSlash(host.Config))
}

func (result *Inventory) Add(alias string, host Host) error {
	if err := ValidateAlias(alias); err != nil {
		return err
	}
	if result.Hosts == nil {
		result.Hosts = map[string]Host{}
	}
	if _, exists := result.Hosts[alias]; exists {
		return errs.New(errs.InventoryInvalid, "host alias already exists: "+alias, nil)
	}
	result.Hosts[alias] = host
	if err := Validate(*result); err != nil {
		delete(result.Hosts, alias)
		return err
	}
	return nil
}

func (result *Inventory) Remove(alias string) error {
	if _, exists := result.Hosts[alias]; !exists {
		return errs.New(errs.InventoryInvalid, "unknown host alias: "+alias, nil)
	}
	delete(result.Hosts, alias)
	return nil
}

func (result Inventory) SortedAliases() []string {
	aliases := make([]string, 0, len(result.Hosts))
	for alias := range result.Hosts {
		aliases = append(aliases, alias)
	}
	sort.Strings(aliases)
	return aliases
}

// CanonicalTOML is intentionally handwritten over a map-free data model. It
// gives stable order and remains a small, easy-to-review user-authored format.
func (result Inventory) CanonicalTOML() ([]byte, error) {
	if err := Validate(result); err != nil {
		return nil, err
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "version = %d\n", result.Version)
	for _, alias := range result.SortedAliases() {
		host := result.Hosts[alias]
		fmt.Fprintf(&builder, "\n[hosts.%s]\n", alias)
		fmt.Fprintf(&builder, "target = %s\n", tomlString(host.Target))
		if host.Config != "" {
			fmt.Fprintf(&builder, "config = %s\n", tomlString(filepath.ToSlash(host.Config)))
		}
	}
	return []byte(builder.String()), nil
}

func WriteFile(filename string, result Inventory) error {
	contents, err := result.CanonicalTOML()
	if err != nil {
		return err
	}
	directory := filepath.Dir(filename)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create inventory directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".bebop-hosts-*")
	if err != nil {
		return fmt.Errorf("create temporary inventory: %w", err)
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return fmt.Errorf("set inventory permissions: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		temporary.Close()
		return fmt.Errorf("write inventory: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync inventory: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close inventory: %w", err)
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return fmt.Errorf("replace inventory atomically: %w", err)
	}
	return nil
}

func tomlString(value string) string {
	// Inputs are validated to have no control characters. TOML's basic-string
	// escaping is therefore sufficient and avoids Go-only \x escapes.
	return `"` + strings.NewReplacer(`\\`, `\\\\`, `"`, `\\"`).Replace(value) + `"`
}
