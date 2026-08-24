package recipes

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
)

const ComposeFilename = "compose.yaml"
const ProvenanceFilename = "bebop.recipe.json"

// WriteResult describes only controller-side authoring changes.
type WriteResult struct {
	ConfigPath    string   `json:"config_path"`
	Created       []string `json:"created"`
	Updated       []string `json:"updated"`
	SecretExample string   `json:"secret_example,omitempty"`
}

// Initialize writes a fresh materialized source tree and appends exactly one
// validated ordinary service declaration. It never contacts a target.
func Initialize(configPath string, current config.Config, materialization Materialization) (WriteResult, error) {
	if err := config.Validate(current); err != nil {
		return WriteResult{}, err
	}
	for _, service := range current.Services {
		if service.Name == materialization.Service.Name {
			return WriteResult{}, fmt.Errorf("service %q is already declared", service.Name)
		}
	}
	root, absoluteConfig, err := configRoot(configPath)
	if err != nil {
		return WriteResult{}, err
	}
	source, err := containedOutput(root, materialization.Source)
	if err != nil {
		return WriteResult{}, err
	}
	if _, err := os.Lstat(source); err == nil {
		return WriteResult{}, fmt.Errorf("recipe output %s already exists", materialization.Source)
	} else if !os.IsNotExist(err) {
		return WriteResult{}, err
	}
	if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
		return WriteResult{}, fmt.Errorf("create recipe output parent: %w", err)
	}
	if err := ensureContained(root, filepath.Dir(source)); err != nil {
		return WriteResult{}, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(source), ".bebop-recipe-")
	if err != nil {
		return WriteResult{}, err
	}
	defer os.RemoveAll(stage)
	if err := writeSource(stage, materialization); err != nil {
		return WriteResult{}, err
	}
	if err := os.Rename(stage, source); err != nil {
		return WriteResult{}, fmt.Errorf("publish recipe source: %w", err)
	}
	published := true
	defer func() {
		if published {
			_ = os.RemoveAll(source)
		}
	}()
	result := WriteResult{ConfigPath: absoluteConfig, Created: []string{filepath.Join(materialization.Source, ComposeFilename), filepath.Join(materialization.Source, ProvenanceFilename)}}
	createdExample := false
	if len(materialization.SecretExample) > 0 {
		example, created, err := writeSecretExample(root, materialization.Provenance.SecretFile, materialization.SecretExample)
		if err != nil {
			return WriteResult{}, err
		}
		createdExample = created
		result.Created = append(result.Created, example)
		result.SecretExample = example
	}
	if err := appendService(absoluteConfig, materialization.Service); err != nil {
		if createdExample {
			_ = os.Remove(filepath.Join(root, filepath.FromSlash(result.SecretExample)))
		}
		return WriteResult{}, err
	}
	published = false
	result.Updated = []string{absoluteConfig}
	return result, nil
}

// LoadProvenance validates local generated metadata before recipe management
// uses it. Normal generic service plan/apply intentionally never calls this.
func LoadProvenance(filename string) (Provenance, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return Provenance{}, err
	}
	var provenance Provenance
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&provenance); err != nil {
		return Provenance{}, fmt.Errorf("invalid recipe provenance: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Provenance{}, fmt.Errorf("invalid recipe provenance trailing data")
	}
	if err := validateProvenance(provenance); err != nil {
		return Provenance{}, err
	}
	fingerprint, err := provenanceFingerprint(provenance)
	if err != nil || provenance.Fingerprint != fingerprint {
		return Provenance{}, fmt.Errorf("recipe provenance fingerprint does not match")
	}
	return provenance, nil
}

// CheckDrift blocks recipe-management overwrites when generated source has
// been edited or extended. Removing provenance is the deliberate ejection path.
func CheckDrift(source string, provenance Provenance) error {
	if err := validateProvenance(provenance); err != nil {
		return err
	}
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("recipe source is not a real directory")
	}
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	if len(entries) != 2 {
		return fmt.Errorf("recipe-generated source diverged; remove provenance to manage it manually")
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || (entry.Name() != ComposeFilename && entry.Name() != ProvenanceFilename) {
			return fmt.Errorf("recipe-generated source diverged; remove provenance to manage it manually")
		}
		seen[entry.Name()] = true
	}
	if !seen[ComposeFilename] || !seen[ProvenanceFilename] {
		return fmt.Errorf("recipe-generated source is incomplete")
	}
	compose, err := os.ReadFile(filepath.Join(source, ComposeFilename))
	if err != nil {
		return err
	}
	if hash(compose) != provenance.ComposeSHA256 {
		return fmt.Errorf("recipe-generated Compose source diverged; remove provenance to manage it manually")
	}
	return nil
}

// ValidateUpgrade performs the non-mutating checks shared by upgrade preview
// and publication. Keeping this boundary explicit means a dry run cannot claim
// an upgrade is ready when the real write would reject provenance drift.
func ValidateUpgrade(configPath string, current config.Config, source string, previous Provenance, next Materialization) error {
	if previous.Source != next.Source || previous.RecipeID != next.Recipe.ID {
		return fmt.Errorf("recipe upgrade provenance does not match requested service")
	}
	root, _, err := configRoot(configPath)
	if err != nil {
		return err
	}
	if err := ensureContained(root, source); err != nil {
		return err
	}
	if err := CheckDrift(source, previous); err != nil {
		return err
	}
	if compareVersion(next.Recipe.Version, previous.RecipeVersion) <= 0 {
		return fmt.Errorf("recipe upgrade version %s must be newer than %s", next.Recipe.Version, previous.RecipeVersion)
	}
	service, found := configuredService(current, next.Source)
	if !found {
		return fmt.Errorf("recipe provenance source is not declared by the configuration")
	}
	if !sameServiceContract(service, next.Service) {
		return fmt.Errorf("recipe upgrade changes service secret or persistent-data declarations; no automatic data migration is available")
	}
	if !sameStrings(previous.SecretParameters, next.Provenance.SecretParameters) || previous.SecretFile != next.Provenance.SecretFile {
		return fmt.Errorf("recipe upgrade changes secret requirements; update the secret reference explicitly before upgrading")
	}
	return nil
}

// Upgrade re-materializes a provenance-validated source in place. It does not
// edit a target or config declaration; incompatible persistent state and secret
// requirements are blocked before any controller file changes.
func Upgrade(configPath string, current config.Config, source string, previous Provenance, next Materialization) (WriteResult, error) {
	if err := ValidateUpgrade(configPath, current, source, previous, next); err != nil {
		return WriteResult{}, err
	}
	_, absoluteConfig, err := configRoot(configPath)
	if err != nil {
		return WriteResult{}, err
	}
	stage, err := os.MkdirTemp(filepath.Dir(source), ".bebop-recipe-upgrade-")
	if err != nil {
		return WriteResult{}, err
	}
	defer os.RemoveAll(stage)
	if err := writeSource(stage, next); err != nil {
		return WriteResult{}, err
	}
	backup := source + ".bebop-recipe-previous"
	if _, err := os.Lstat(backup); err == nil {
		return WriteResult{}, fmt.Errorf("recipe upgrade recovery path already exists")
	} else if !os.IsNotExist(err) {
		return WriteResult{}, err
	}
	if err := os.Rename(source, backup); err != nil {
		return WriteResult{}, fmt.Errorf("stage recipe upgrade: %w", err)
	}
	if err := os.Rename(stage, source); err != nil {
		_ = os.Rename(backup, source)
		return WriteResult{}, fmt.Errorf("publish recipe upgrade: %w", err)
	}
	if err := os.RemoveAll(backup); err != nil {
		return WriteResult{}, fmt.Errorf("remove replaced generated source: %w", err)
	}
	return WriteResult{ConfigPath: absoluteConfig, Updated: []string{filepath.Join(next.Source, ComposeFilename), filepath.Join(next.Source, ProvenanceFilename)}}, nil
}

func configuredService(current config.Config, source string) (config.Service, bool) {
	for _, service := range current.Services {
		if service.Source == source {
			return service, true
		}
	}
	return config.Service{}, false
}

func sameServiceContract(current, next config.Service) bool {
	if current.Name != next.Name || current.Source != next.Source || current.Type != next.Type || current.State != next.State || current.HealthTimeout != next.HealthTimeout || current.SecretEnvFile != next.SecretEnvFile || current.Backup != next.Backup || len(current.Data) != len(next.Data) {
		return false
	}
	for index := range current.Data {
		if current.Data[index] != next.Data[index] {
			return false
		}
	}
	return true
}

func writeSource(directory string, materialization Materialization) error {
	if err := os.WriteFile(filepath.Join(directory, ComposeFilename), materialization.Compose, 0o644); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(materialization.Provenance, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, ProvenanceFilename), append(encoded, '\n'), 0o644); err != nil {
		return err
	}
	return nil
}

func configRoot(filename string) (string, string, error) {
	abs, err := filepath.Abs(filename)
	if err != nil {
		return "", "", err
	}
	root, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", "", err
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return "", "", fmt.Errorf("configuration directory is not a real directory")
	}
	return root, abs, nil
}

func containedOutput(root, logical string) (string, error) {
	if err := config.ValidateControllerRelativePath(logical, false); err != nil {
		return "", err
	}
	output := filepath.Join(root, filepath.FromSlash(logical))
	if err := ensureContained(root, filepath.Dir(output)); err != nil && !os.IsNotExist(err) {
		return "", err
	}
	relative, err := filepath.Rel(root, output)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("recipe output escapes configuration directory")
	}
	return output, nil
}

func ensureContained(root, candidate string) error {
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(root, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return fmt.Errorf("recipe path escapes configuration directory")
	}
	return nil
}

func appendService(filename string, service config.Service) error {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	info, err := os.Stat(filename)
	if err != nil {
		return err
	}
	addition, err := serviceTOML(service)
	if err != nil {
		return err
	}
	updated := append(append(bytesTrimRight(contents, "\n"), '\n', '\n'), addition...)
	return atomicWrite(filename, updated, info.Mode().Perm())
}

func serviceTOML(service config.Service) ([]byte, error) {
	probe := config.Defaults()
	probe.Services = []config.Service{service}
	if err := config.Validate(probe); err != nil {
		return nil, err
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "[services.%s]\n", service.Name)
	fmt.Fprintf(&builder, "type = %s\nsource = %s\nstate = %s\nhealth_timeout = %s\n", tomlString(service.Type), tomlString(service.Source), tomlString(service.State), tomlString(service.HealthTimeout))
	if service.SecretEnvFile != "" {
		fmt.Fprintf(&builder, "secret_env_file = %s\n", tomlString(service.SecretEnvFile))
	}
	for _, resource := range service.Data {
		fmt.Fprintf(&builder, "\n[[services.%s.data]]\nname = %s\ntype = %s\n", service.Name, tomlString(resource.Name), tomlString(resource.Type))
		if resource.Type == "volume" {
			fmt.Fprintf(&builder, "volume = %s\n", tomlString(resource.Volume))
		} else {
			fmt.Fprintf(&builder, "path = %s\n", tomlString(resource.Path))
		}
	}
	fmt.Fprintf(&builder, "\n[services.%s.backup]\nconsistency = %s\n", service.Name, tomlString(service.Backup.Consistency))
	return []byte(builder.String()), nil
}

func writeSecretExample(root, logical string, contents []byte) (string, bool, error) {
	if logical == "" {
		return "", false, nil
	}
	exampleLogical := logical + ".example"
	filename, err := containedOutput(root, exampleLogical)
	if err != nil {
		return "", false, err
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return "", false, err
	}
	if err := ensureContained(root, filepath.Dir(filename)); err != nil {
		return "", false, err
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return exampleLogical, false, nil
		}
		return "", false, err
	}
	defer file.Close()
	if _, err := file.Write(contents); err != nil {
		return "", false, err
	}
	if err := file.Sync(); err != nil {
		return "", false, err
	}
	return exampleLogical, true, nil
}

func atomicWrite(filename string, contents []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(filename), ".bebop-recipe-config-")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, filename)
}

func tomlString(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func bytesTrimRight(value []byte, cutset string) []byte {
	return []byte(strings.TrimRight(string(value), cutset))
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
