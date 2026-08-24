// Package recipes provides controller-side, deterministic authoring helpers.
// It deliberately produces ordinary config.Service declarations and Compose
// source files; it has no target transport, planner, or apply capability.
package recipes

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

const SchemaVersion = 1
const ProvenanceSchemaVersion = 1

//go:embed builtin
var builtinFiles embed.FS

var recipeIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
var parameterNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
var environmentNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
var semverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var placeholderPattern = regexp.MustCompile(`\$\{([a-z][a-z0-9-]{0,62})\}`)

// Catalog contains locally available recipes. Its deterministic lookup is
// intentionally independent of filesystem iteration order.
type Catalog struct {
	byID map[string][]Recipe
}

// Recipe is immutable validated metadata plus an internal Compose template.
// Image/application version remains distinct from recipe version.
type Recipe struct {
	SchemaVersion      int            `json:"schema_version"`
	ID                 string         `json:"id"`
	Version            string         `json:"version"`
	Name               string         `json:"name"`
	Description        string         `json:"description"`
	Homepage           string         `json:"homepage,omitempty"`
	License            string         `json:"license,omitempty"`
	ApplicationVersion string         `json:"application_version"`
	Images             []string       `json:"images"`
	Architectures      []string       `json:"architectures"`
	Health             string         `json:"health"`
	HealthTimeout      string         `json:"health_timeout"`
	Parameters         []Parameter    `json:"parameters"`
	Data               []DataResource `json:"data,omitempty"`
	Secrets            []Secret       `json:"secrets,omitempty"`
	Fingerprint        string         `json:"fingerprint"`
	compose            []byte
}

// Parameter is a small, non-executable scalar input schema. Defaults are
// canonical textual values so all external CLI input has one normalization path.
type Parameter struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Required   bool     `json:"required"`
	Default    string   `json:"default,omitempty"`
	HasDefault bool     `json:"has_default"`
	Minimum    *int64   `json:"minimum,omitempty"`
	Maximum    *int64   `json:"maximum,omitempty"`
	Enum       []string `json:"enum,omitempty"`
	Pattern    string   `json:"pattern,omitempty"`
}

// DataResource compiles directly into config.DataResource and therefore M4's
// existing explicit backup authorization model.
type DataResource struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Volume string `json:"volume,omitempty"`
	Path   string `json:"path,omitempty"`
}

// Secret describes an environment variable expected in the existing M3 secret
// env file. Values are never accepted as materialization parameters.
type Secret struct {
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Required    bool   `json:"required"`
}

// ParameterValue is a normalized non-secret value safe for provenance and JSON.
type ParameterValue struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Input is the normalized request passed to Materialize.
type Input struct {
	Values     []ParameterValue `json:"parameters"`
	SecretFile string           `json:"secret_file,omitempty"`
}

// Request selects the output service identity and local source path. Source is
// controller-relative to the config that will declare the service.
type Request struct {
	Service    string
	Source     string
	Parameters []string
	SecretFile string
}

// Materialization consists only of ordinary Compose/config inputs and a local
// provenance file. It intentionally does not reference a target host.
type Materialization struct {
	Recipe        Recipe         `json:"recipe"`
	Service       config.Service `json:"service"`
	Source        string         `json:"source"`
	Compose       []byte         `json:"-"`
	Provenance    Provenance     `json:"provenance"`
	SecretExample []byte         `json:"-"`
}

// Provenance is generated metadata, not desired-state authority. It lets recipe
// management detect drift while normal generic Bebop service handling ignores it.
type Provenance struct {
	SchemaVersion              int              `json:"schema_version"`
	RecipeID                   string           `json:"recipe_id"`
	RecipeVersion              string           `json:"recipe_version"`
	RecipeFingerprint          string           `json:"recipe_fingerprint"`
	Parameters                 []ParameterValue `json:"parameters"`
	SecretFile                 string           `json:"secret_file,omitempty"`
	SecretParameters           []string         `json:"secret_parameters,omitempty"`
	Source                     string           `json:"source"`
	ComposeSHA256              string           `json:"compose_sha256"`
	MaterializationFingerprint string           `json:"materialization_fingerprint"`
	Fingerprint                string           `json:"fingerprint"`
}

type rawRecipe struct {
	SchemaVersion int `toml:"schema_version"`
	Recipe        struct {
		ID                 string   `toml:"id"`
		Version            string   `toml:"version"`
		Name               string   `toml:"name"`
		Description        string   `toml:"description"`
		Homepage           string   `toml:"homepage"`
		License            string   `toml:"license"`
		ApplicationVersion string   `toml:"application_version"`
		Images             []string `toml:"images"`
	} `toml:"recipe"`
	Compatibility struct {
		Architectures []string `toml:"architectures"`
	} `toml:"compatibility"`
	Service struct {
		Health        string `toml:"health"`
		HealthTimeout string `toml:"health_timeout"`
	} `toml:"service"`
	Parameters []struct {
		Name     string   `toml:"name"`
		Type     string   `toml:"type"`
		Required bool     `toml:"required"`
		Default  *string  `toml:"default"`
		Minimum  *int64   `toml:"minimum"`
		Maximum  *int64   `toml:"maximum"`
		Enum     []string `toml:"enum"`
		Pattern  string   `toml:"pattern"`
	} `toml:"parameters"`
	Data    []DataResource `toml:"data"`
	Secrets []Secret       `toml:"secrets"`
}

var builtinOnce sync.Once
var builtinCatalog Catalog
var builtinErr error

// Builtin returns the corpus embedded into the controller binary, so discovery
// and materialization remain offline after installation.
func Builtin() (Catalog, error) {
	builtinOnce.Do(func() {
		root, err := fs.Sub(builtinFiles, "builtin")
		if err != nil {
			builtinErr = err
			return
		}
		builtinCatalog, builtinErr = Load(root)
	})
	return builtinCatalog, builtinErr
}

// Load parses an fs containing <id>/<version>/{recipe.toml,compose.yaml}.
// It is useful for tests and deliberately has no local-path execution surface.
func Load(root fs.FS) (Catalog, error) {
	result := Catalog{byID: map[string][]Recipe{}}
	paths := make([]string, 0)
	if err := fs.WalkDir(root, ".", func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() && path.Base(filename) == "recipe.toml" {
			paths = append(paths, filename)
		}
		return nil
	}); err != nil {
		return Catalog{}, err
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		return Catalog{}, fmt.Errorf("recipe corpus contains no recipe.toml files")
	}
	for _, metadataPath := range paths {
		directory := path.Dir(metadataPath)
		parts := strings.Split(directory, "/")
		if len(parts) != 2 || !recipeIDPattern.MatchString(parts[0]) || !semverPattern.MatchString(parts[1]) {
			return Catalog{}, fmt.Errorf("recipe metadata path %q must use <id>/<semantic-version>", metadataPath)
		}
		metadata, err := fs.ReadFile(root, metadataPath)
		if err != nil {
			return Catalog{}, err
		}
		compose, err := fs.ReadFile(root, path.Join(directory, "compose.yaml"))
		if err != nil {
			return Catalog{}, fmt.Errorf("recipe %s/%s has no compose.yaml: %w", parts[0], parts[1], err)
		}
		recipe, err := decode(metadata, compose)
		if err != nil {
			return Catalog{}, fmt.Errorf("recipe %s/%s: %w", parts[0], parts[1], err)
		}
		if recipe.ID != parts[0] || recipe.Version != parts[1] {
			return Catalog{}, fmt.Errorf("recipe path %s/%s does not match metadata %s@%s", parts[0], parts[1], recipe.ID, recipe.Version)
		}
		result.byID[recipe.ID] = append(result.byID[recipe.ID], recipe)
	}
	for id, entries := range result.byID {
		sort.Slice(entries, func(i, j int) bool { return compareVersion(entries[i].Version, entries[j].Version) < 0 })
		for index := 1; index < len(entries); index++ {
			if entries[index-1].Version == entries[index].Version {
				return Catalog{}, fmt.Errorf("duplicate recipe %s@%s", id, entries[index].Version)
			}
		}
		result.byID[id] = entries
	}
	return result, nil
}

func decode(contents, compose []byte) (Recipe, error) {
	var raw rawRecipe
	decoder := toml.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return Recipe{}, err
	}
	result := Recipe{SchemaVersion: raw.SchemaVersion, ID: raw.Recipe.ID, Version: raw.Recipe.Version, Name: raw.Recipe.Name, Description: raw.Recipe.Description, Homepage: raw.Recipe.Homepage, License: raw.Recipe.License, ApplicationVersion: raw.Recipe.ApplicationVersion, Images: append([]string(nil), raw.Recipe.Images...), Architectures: append([]string(nil), raw.Compatibility.Architectures...), Health: raw.Service.Health, HealthTimeout: raw.Service.HealthTimeout, Data: append([]DataResource(nil), raw.Data...), Secrets: append([]Secret(nil), raw.Secrets...), compose: append([]byte(nil), compose...)}
	for _, parameter := range raw.Parameters {
		value := Parameter{Name: parameter.Name, Type: parameter.Type, Required: parameter.Required, Minimum: parameter.Minimum, Maximum: parameter.Maximum, Enum: append([]string(nil), parameter.Enum...), Pattern: parameter.Pattern}
		if parameter.Default != nil {
			value.Default, value.HasDefault = *parameter.Default, true
		}
		result.Parameters = append(result.Parameters, value)
	}
	if err := result.validate(); err != nil {
		return Recipe{}, err
	}
	fingerprint, err := result.semanticFingerprint()
	if err != nil {
		return Recipe{}, err
	}
	result.Fingerprint = fingerprint
	return result, nil
}

func (catalog Catalog) List() []Recipe {
	ids := make([]string, 0, len(catalog.byID))
	for id := range catalog.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]Recipe, 0, len(ids))
	for _, id := range ids {
		versions := catalog.byID[id]
		result = append(result, cloneRecipe(versions[len(versions)-1]))
	}
	return result
}

func (catalog Catalog) Find(id, version string) (Recipe, error) {
	entries, found := catalog.byID[id]
	if !found {
		return Recipe{}, fmt.Errorf("unknown recipe %q", id)
	}
	if version == "" {
		return entries[len(entries)-1], nil
	}
	for _, recipe := range entries {
		if recipe.Version == version {
			return cloneRecipe(recipe), nil
		}
	}
	return Recipe{}, fmt.Errorf("recipe %q does not include version %s", id, version)
}

func cloneRecipe(recipe Recipe) Recipe {
	result := recipe
	result.Images = append([]string(nil), recipe.Images...)
	result.Architectures = append([]string(nil), recipe.Architectures...)
	result.Parameters = make([]Parameter, len(recipe.Parameters))
	for index, parameter := range recipe.Parameters {
		result.Parameters[index] = parameter
		result.Parameters[index].Enum = append([]string(nil), parameter.Enum...)
	}
	result.Data = append([]DataResource(nil), recipe.Data...)
	result.Secrets = append([]Secret(nil), recipe.Secrets...)
	result.compose = append([]byte(nil), recipe.compose...)
	return result
}

func (catalog Catalog) Validate() error {
	for _, recipe := range catalog.List() {
		for _, candidate := range catalog.byID[recipe.ID] {
			if err := candidate.validate(); err != nil {
				return fmt.Errorf("recipe %s@%s: %w", candidate.ID, candidate.Version, err)
			}
		}
	}
	return nil
}

func (recipe Recipe) validate() error {
	if recipe.SchemaVersion != SchemaVersion || !recipeIDPattern.MatchString(recipe.ID) || !semverPattern.MatchString(recipe.Version) || recipe.Name == "" || recipe.Description == "" || recipe.ApplicationVersion == "" || len(recipe.Images) == 0 {
		return fmt.Errorf("invalid required recipe metadata")
	}
	if len(recipe.Architectures) == 0 || recipe.Health == "" || recipe.HealthTimeout == "" {
		return fmt.Errorf("recipe must declare architectures and health behavior")
	}
	previous := ""
	for _, architecture := range recipe.Architectures {
		if (architecture != "amd64" && architecture != "arm64") || architecture <= previous {
			return fmt.Errorf("architectures must be sorted unique amd64/arm64 values")
		}
		previous = architecture
	}
	for _, image := range recipe.Images {
		if !pinnedImage(image) {
			return fmt.Errorf("recipe images must use explicit non-latest tags")
		}
	}
	if recipe.Health != "running-only" && recipe.Health != "healthcheck" {
		return fmt.Errorf("health must be running-only or healthcheck")
	}
	if duration, err := time.ParseDuration(recipe.HealthTimeout); err != nil || duration <= 0 {
		return fmt.Errorf("health_timeout must be a positive Go duration")
	}
	previous = ""
	for _, parameter := range recipe.Parameters {
		if !parameterNamePattern.MatchString(parameter.Name) || parameter.Name <= previous {
			return fmt.Errorf("parameters must have sorted unique safe names")
		}
		previous = parameter.Name
		if !validParameterType(parameter.Type) {
			return fmt.Errorf("parameter %q has unsupported type %q", parameter.Name, parameter.Type)
		}
		if parameter.Type == "secret" {
			return fmt.Errorf("secret parameters belong in [[secrets]], not [[parameters]]")
		}
		if parameter.Minimum != nil && parameter.Maximum != nil && *parameter.Minimum > *parameter.Maximum {
			return fmt.Errorf("parameter %q has an invalid range", parameter.Name)
		}
		if parameter.Type == "enum" && len(parameter.Enum) == 0 {
			return fmt.Errorf("enum parameter %q requires values", parameter.Name)
		}
		if parameter.Pattern != "" {
			if _, err := regexp.Compile(parameter.Pattern); err != nil {
				return fmt.Errorf("parameter %q pattern: %w", parameter.Name, err)
			}
		}
		if parameter.HasDefault {
			if _, err := normalize(parameter, parameter.Default); err != nil {
				return fmt.Errorf("parameter %q default: %w", parameter.Name, err)
			}
		} else if !parameter.Required {
			return fmt.Errorf("optional parameter %q requires a default", parameter.Name)
		}
	}
	previous = ""
	for _, secret := range recipe.Secrets {
		if !parameterNamePattern.MatchString(secret.Name) || secret.Name <= previous || !environmentNamePattern.MatchString(secret.Environment) || !secret.Required {
			return fmt.Errorf("secrets must have sorted unique required names and safe environment keys")
		}
		previous = secret.Name
	}
	data := make([]config.DataResource, 0, len(recipe.Data))
	for _, resource := range recipe.Data {
		data = append(data, config.DataResource{Name: resource.Name, Type: resource.Type, Volume: resource.Volume, Path: resource.Path})
	}
	probe := config.Defaults()
	probe.Services = []config.Service{{Name: "recipe", Type: "compose", Source: "services/recipe", State: "running", HealthTimeout: recipe.HealthTimeout, Data: data, Backup: config.ServiceBackup{Consistency: "stop"}}}
	if len(recipe.Secrets) > 0 {
		probe.Services[0].SecretEnvFile = "secrets/recipe.env"
	}
	if err := config.Validate(probe); err != nil {
		return fmt.Errorf("persistent resource declaration: %w", err)
	}
	values, err := recipe.resolve(nil, nil, "")
	if err != nil && len(recipe.Secrets) == 0 {
		return err
	}
	if len(recipe.Secrets) > 0 {
		values, err = recipe.resolve(nil, nil, "secrets/recipe.env")
		if err != nil {
			return err
		}
	}
	_, err = recipe.render(values)
	return err
}

func pinnedImage(image string) bool {
	if image == "" || strings.HasSuffix(image, ":latest") || strings.ContainsAny(image, " \t\r\n") {
		return false
	}
	if strings.Contains(image, "@sha256:") {
		return true
	}
	last := image[strings.LastIndex(image, "/")+1:]
	return strings.Contains(last, ":")
}

func validParameterType(value string) bool {
	switch value {
	case "string", "integer", "boolean", "enum", "port", "path":
		return true
	default:
		return false
	}
}

func (recipe Recipe) semanticFingerprint() (string, error) {
	semantic := struct {
		SchemaVersion      int            `json:"schema_version"`
		ID                 string         `json:"id"`
		Version            string         `json:"version"`
		ApplicationVersion string         `json:"application_version"`
		Images             []string       `json:"images"`
		Architectures      []string       `json:"architectures"`
		Health             string         `json:"health"`
		HealthTimeout      string         `json:"health_timeout"`
		Parameters         []Parameter    `json:"parameters"`
		Data               []DataResource `json:"data"`
		Secrets            []Secret       `json:"secrets"`
		ComposeSHA256      string         `json:"compose_sha256"`
	}{SchemaVersion: recipe.SchemaVersion, ID: recipe.ID, Version: recipe.Version, ApplicationVersion: recipe.ApplicationVersion, Images: recipe.Images, Architectures: recipe.Architectures, Health: recipe.Health, HealthTimeout: recipe.HealthTimeout, Parameters: recipe.Parameters, Data: recipe.Data, Secrets: recipe.Secrets, ComposeSHA256: hash(recipe.compose)}
	return hashJSON(semantic)
}

func (recipe Recipe) Resolve(assignments []string, secretFile string) (Input, error) {
	return recipe.resolve(assignments, nil, secretFile)
}

// Reuse normalizes an explicit upgrade request while preserving values from a
// prior validated provenance entry only when the new schema still accepts them.
func (recipe Recipe) Reuse(previous []ParameterValue, assignments []string, secretFile string) (Input, error) {
	return recipe.resolve(assignments, previous, secretFile)
}

// SupportsArchitecture is intentionally a metadata check only; target access
// remains owned by Bebop's normal inspection and planning path.
func (recipe Recipe) SupportsArchitecture(architecture string) bool {
	for _, supported := range recipe.Architectures {
		if supported == architecture {
			return true
		}
	}
	return false
}

func (recipe Recipe) resolve(assignments []string, existing []ParameterValue, secretFile string) (Input, error) {
	provided := map[string]string{}
	for _, assignment := range assignments {
		name, value, found := strings.Cut(assignment, "=")
		if !found || name == "" {
			return Input{}, fmt.Errorf("parameters must use name=value")
		}
		if _, exists := provided[name]; exists {
			return Input{}, fmt.Errorf("parameter %q was provided more than once", name)
		}
		provided[name] = value
	}
	previous := map[string]ParameterValue{}
	for _, value := range existing {
		if value.Name == "" || previous[value.Name].Name != "" {
			return Input{}, fmt.Errorf("invalid stored recipe parameters")
		}
		previous[value.Name] = value
	}
	declared := map[string]Parameter{}
	for _, parameter := range recipe.Parameters {
		declared[parameter.Name] = parameter
	}
	for name := range provided {
		if _, found := declared[name]; !found {
			return Input{}, fmt.Errorf("unknown parameter %q", name)
		}
	}
	result := Input{}
	for _, parameter := range recipe.Parameters {
		value, found := provided[parameter.Name]
		if !found {
			if previousValue, exists := previous[parameter.Name]; exists {
				value, found = previousValue.Value, true
			} else if parameter.HasDefault {
				value, found = parameter.Default, true
			}
		}
		if !found {
			return Input{}, fmt.Errorf("required parameter %q was not provided", parameter.Name)
		}
		normalized, err := normalize(parameter, value)
		if err != nil {
			return Input{}, fmt.Errorf("invalid parameter %q: %w", parameter.Name, err)
		}
		result.Values = append(result.Values, ParameterValue{Name: parameter.Name, Type: parameter.Type, Value: normalized})
	}
	if len(recipe.Secrets) > 0 {
		if secretFile == "" {
			return Input{}, fmt.Errorf("recipe %q requires --secret-file for %s", recipe.ID, strings.Join(recipe.secretNames(), ", "))
		}
		if err := config.ValidateControllerRelativePath(secretFile, true); err != nil {
			return Input{}, fmt.Errorf("secret file %w", err)
		}
		result.SecretFile = strings.ReplaceAll(secretFile, "\\", "/")
	} else if secretFile != "" {
		return Input{}, fmt.Errorf("recipe %q does not declare secret parameters", recipe.ID)
	}
	return result, nil
}

func normalize(parameter Parameter, value string) (string, error) {
	if strings.ContainsRune(value, '\x00') || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("must not contain control characters")
	}
	var normalized string
	switch parameter.Type {
	case "string":
		normalized = value
	case "integer", "port":
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return "", fmt.Errorf("expected integer")
		}
		if parameter.Type == "port" && (parsed < 1 || parsed > 65535) {
			return "", fmt.Errorf("expected TCP port in range 1-65535")
		}
		if parameter.Minimum != nil && parsed < *parameter.Minimum || parameter.Maximum != nil && parsed > *parameter.Maximum {
			return "", fmt.Errorf("must be within declared range")
		}
		normalized = strconv.FormatInt(parsed, 10)
	case "boolean":
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return "", fmt.Errorf("expected boolean")
		}
		normalized = strconv.FormatBool(parsed)
	case "enum":
		found := false
		for _, allowed := range parameter.Enum {
			if value == allowed {
				found = true
				break
			}
		}
		if !found {
			return "", fmt.Errorf("must be one of %s", strings.Join(parameter.Enum, ", "))
		}
		normalized = value
	case "path":
		if value == "" || strings.Contains(value, "\\") || path.Clean(value) != value || strings.HasPrefix(value, "../") || value == ".." {
			return "", fmt.Errorf("must be a clean non-traversing POSIX path")
		}
		normalized = value
	default:
		return "", fmt.Errorf("unsupported type %q", parameter.Type)
	}
	if parameter.Pattern != "" {
		pattern := regexp.MustCompile(parameter.Pattern)
		if !pattern.MatchString(normalized) {
			return "", fmt.Errorf("does not match required pattern")
		}
	}
	return normalized, nil
}

func (recipe Recipe) Materialize(request Request) (Materialization, error) {
	if !recipeIDPattern.MatchString(request.Service) {
		return Materialization{}, fmt.Errorf("service name must be a safe Bebop service identifier")
	}
	if err := config.ValidateControllerRelativePath(request.Source, false); err != nil {
		return Materialization{}, fmt.Errorf("source path %w", err)
	}
	input, err := recipe.Resolve(request.Parameters, request.SecretFile)
	if err != nil {
		return Materialization{}, err
	}
	return recipe.MaterializeWithInput(request, input)
}

// MaterializeWithInput exists for upgrades after Reuse has validated compatible
// previous values. Callers must obtain input through Resolve or Reuse.
func (recipe Recipe) MaterializeWithInput(request Request, input Input) (Materialization, error) {
	if !recipeIDPattern.MatchString(request.Service) {
		return Materialization{}, fmt.Errorf("service name must be a safe Bebop service identifier")
	}
	if err := config.ValidateControllerRelativePath(request.Source, false); err != nil {
		return Materialization{}, fmt.Errorf("source path %w", err)
	}
	compose, err := recipe.render(input)
	if err != nil {
		return Materialization{}, err
	}
	compose = append([]byte("# Generated from Bebop recipe "+recipe.ID+"@"+recipe.Version+"\n"), compose...)
	data := make([]config.DataResource, 0, len(recipe.Data))
	for _, resource := range recipe.Data {
		data = append(data, config.DataResource{Name: resource.Name, Type: resource.Type, Volume: resource.Volume, Path: resource.Path})
	}
	service := config.Service{Name: request.Service, Type: "compose", Source: strings.ReplaceAll(request.Source, "\\", "/"), State: "running", HealthTimeout: recipe.HealthTimeout, Data: data, Backup: config.ServiceBackup{Consistency: "stop"}}
	if input.SecretFile != "" {
		service.SecretEnvFile = input.SecretFile
	}
	probe := config.Defaults()
	probe.Services = []config.Service{service}
	if err := config.Validate(probe); err != nil {
		return Materialization{}, err
	}
	materializationFingerprint, err := materializationFingerprint(recipe, input)
	if err != nil {
		return Materialization{}, err
	}
	provenance := Provenance{SchemaVersion: ProvenanceSchemaVersion, RecipeID: recipe.ID, RecipeVersion: recipe.Version, RecipeFingerprint: recipe.Fingerprint, Parameters: input.Values, SecretFile: input.SecretFile, SecretParameters: recipe.secretNames(), Source: service.Source, ComposeSHA256: hash(compose), MaterializationFingerprint: materializationFingerprint}
	if err := provenance.Seal(); err != nil {
		return Materialization{}, err
	}
	var example []byte
	if len(recipe.Secrets) > 0 {
		for _, secret := range recipe.Secrets {
			example = append(example, []byte(secret.Environment+"=\n")...)
		}
	}
	return Materialization{Recipe: recipe, Service: service, Source: service.Source, Compose: compose, Provenance: provenance, SecretExample: example}, nil
}

func (recipe Recipe) render(input Input) ([]byte, error) {
	values := map[string]string{}
	for _, value := range input.Values {
		values[value.Name] = value.Value
	}
	var document yaml.Node
	if err := yaml.Unmarshal(recipe.compose, &document); err != nil {
		return nil, fmt.Errorf("invalid Compose template: %w", err)
	}
	if containsAlias(&document) {
		return nil, fmt.Errorf("Compose template must not contain YAML aliases")
	}
	if err := replaceNode(&document, values); err != nil {
		return nil, err
	}
	encoded, err := yaml.Marshal(&document)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(encoded, []byte("${")) {
		return nil, fmt.Errorf("Compose template retains an unresolved placeholder")
	}
	if err := validateRenderedCompose(encoded, recipe); err != nil {
		return nil, err
	}
	return encoded, nil
}

func replaceNode(node *yaml.Node, values map[string]string) error {
	if node.Kind == yaml.ScalarNode && node.Tag == "!!str" {
		var unknown string
		node.Value = placeholderPattern.ReplaceAllStringFunc(node.Value, func(match string) string {
			name := placeholderPattern.FindStringSubmatch(match)[1]
			value, found := values[name]
			if !found {
				unknown = name
				return match
			}
			return value
		})
		if unknown != "" {
			return fmt.Errorf("Compose template references unknown or secret placeholder %q", unknown)
		}
	}
	for _, child := range node.Content {
		if err := replaceNode(child, values); err != nil {
			return err
		}
	}
	return nil
}

func containsAlias(node *yaml.Node) bool {
	if node.Kind == yaml.AliasNode {
		return true
	}
	for _, child := range node.Content {
		if containsAlias(child) {
			return true
		}
	}
	return false
}

func validateRenderedCompose(contents []byte, recipe Recipe) error {
	var document yaml.Node
	if err := yaml.Unmarshal(contents, &document); err != nil {
		return err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("rendered Compose must be a mapping")
	}
	root := document.Content[0]
	servicesNode := mappingValue(root, "services")
	if servicesNode == nil || servicesNode.Kind != yaml.MappingNode || len(servicesNode.Content) == 0 {
		return fmt.Errorf("rendered Compose must contain services")
	}
	images := []string{}
	for index := 0; index+1 < len(servicesNode.Content); index += 2 {
		definition := servicesNode.Content[index+1]
		if definition.Kind != yaml.MappingNode {
			return fmt.Errorf("rendered Compose service must be a mapping")
		}
		image := mappingValue(definition, "image")
		if image == nil || image.Kind != yaml.ScalarNode || image.Value == "" || strings.HasSuffix(image.Value, ":latest") {
			return fmt.Errorf("rendered Compose services require explicit non-latest images")
		}
		images = append(images, image.Value)
	}
	sort.Strings(images)
	expected := append([]string(nil), recipe.Images...)
	sort.Strings(expected)
	if strings.Join(images, "\n") != strings.Join(expected, "\n") {
		return fmt.Errorf("rendered Compose images do not match recipe metadata")
	}
	for _, resource := range recipe.Data {
		if resource.Type != "volume" {
			continue
		}
		volumes := mappingValue(root, "volumes")
		if volumes == nil || mappingValue(volumes, resource.Volume) == nil {
			return fmt.Errorf("rendered Compose does not declare persistent volume %q", resource.Volume)
		}
		if !volumeMounted(servicesNode, resource.Volume) {
			return fmt.Errorf("rendered Compose does not mount persistent volume %q", resource.Volume)
		}
	}
	return nil
}

func volumeMounted(services *yaml.Node, volume string) bool {
	for index := 0; index+1 < len(services.Content); index += 2 {
		definition := services.Content[index+1]
		mounts := mappingValue(definition, "volumes")
		if mounts == nil || mounts.Kind != yaml.SequenceNode {
			continue
		}
		for _, mount := range mounts.Content {
			switch mount.Kind {
			case yaml.ScalarNode:
				if strings.SplitN(mount.Value, ":", 2)[0] == volume {
					return true
				}
			case yaml.MappingNode:
				source := mappingValue(mount, "source")
				if source != nil && source.Kind == yaml.ScalarNode && source.Value == volume {
					return true
				}
			}
		}
	}
	return false
}

func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}
	return nil
}

func materializationFingerprint(recipe Recipe, input Input) (string, error) {
	semantic := struct {
		RecipeFingerprint string           `json:"recipe_fingerprint"`
		Parameters        []ParameterValue `json:"parameters"`
		SecretFile        string           `json:"secret_file,omitempty"`
		SecretParameters  []string         `json:"secret_parameters,omitempty"`
	}{RecipeFingerprint: recipe.Fingerprint, Parameters: input.Values, SecretFile: input.SecretFile, SecretParameters: recipe.secretNames()}
	return hashJSON(semantic)
}

func (recipe Recipe) secretNames() []string {
	result := make([]string, 0, len(recipe.Secrets))
	for _, secret := range recipe.Secrets {
		result = append(result, secret.Name)
	}
	return result
}

func (provenance *Provenance) Seal() error {
	if err := validateProvenance(*provenance); err != nil {
		return err
	}
	fingerprint, err := provenanceFingerprint(*provenance)
	if err != nil {
		return err
	}
	provenance.Fingerprint = fingerprint
	return nil
}

func validateProvenance(provenance Provenance) error {
	if provenance.SchemaVersion != ProvenanceSchemaVersion || !recipeIDPattern.MatchString(provenance.RecipeID) || !semverPattern.MatchString(provenance.RecipeVersion) || len(provenance.RecipeFingerprint) != 64 || len(provenance.ComposeSHA256) != 64 || len(provenance.MaterializationFingerprint) != 64 || provenance.Source == "" {
		return fmt.Errorf("invalid recipe provenance")
	}
	if err := config.ValidateControllerRelativePath(provenance.Source, false); err != nil {
		return fmt.Errorf("invalid recipe provenance source: %w", err)
	}
	if provenance.SecretFile != "" {
		if err := config.ValidateControllerRelativePath(provenance.SecretFile, true); err != nil {
			return fmt.Errorf("invalid recipe provenance secret file: %w", err)
		}
	}
	previous := ""
	for _, parameter := range provenance.Parameters {
		if !parameterNamePattern.MatchString(parameter.Name) || parameter.Name <= previous || !validParameterType(parameter.Type) {
			return fmt.Errorf("invalid recipe provenance parameters")
		}
		previous = parameter.Name
	}
	return nil
}

func provenanceFingerprint(provenance Provenance) (string, error) {
	provenance.Fingerprint = ""
	return hashJSON(provenance)
}

func hash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func hashJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return hash(encoded), nil
}

func compareVersion(left, right string) int {
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for index := range leftParts {
		l, _ := strconv.Atoi(leftParts[index])
		r, _ := strconv.Atoi(rightParts[index])
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	return 0
}
