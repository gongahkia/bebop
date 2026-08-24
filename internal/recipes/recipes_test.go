package recipes

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/services"
)

func TestBuiltinCorpusIsStrictAndDeterministic(t *testing.T) {
	catalog, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatal(err)
	}
	listed := catalog.List()
	if len(listed) != 4 {
		t.Fatalf("expected four first-party recipes, got %#v", listed)
	}
	if listed[0].ID != "forgejo" || listed[3].ID != "whoami" {
		t.Fatalf("recipe list is not sorted by ID: %#v", listed)
	}
	for _, recipe := range listed {
		if !recipe.SupportsArchitecture("amd64") || !recipe.SupportsArchitecture("arm64") {
			t.Fatalf("recipe %s does not represent both supported architectures", recipe.ID)
		}
	}
	first, err := catalog.Find("whoami", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	one, err := first.Materialize(Request{Service: "echo", Source: "services/echo", Parameters: []string{"port=8181"}})
	if err != nil {
		t.Fatal(err)
	}
	two, err := first.Materialize(Request{Service: "echo", Source: "services/echo", Parameters: []string{"port=8181"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(one.Compose) != string(two.Compose) || one.Provenance.MaterializationFingerprint != two.Provenance.MaterializationFingerprint || one.Provenance.Fingerprint != two.Provenance.Fingerprint {
		t.Fatal("identical recipe input materialized nondeterministically")
	}
	if !strings.Contains(string(one.Compose), "8181:80") || !strings.Contains(string(one.Compose), "Generated from Bebop recipe whoami@1.0.0") {
		t.Fatalf("typed port was not rendered into ordinary Compose source: %s", one.Compose)
	}
}

func TestParametersAndSecretsStayTypedAndOutOfGeneratedSource(t *testing.T) {
	catalog, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	vaultwarden, err := catalog.Find("vaultwarden", "")
	if err != nil {
		t.Fatal(err)
	}
	const sentinel = "BEBOP_RECIPE_SECRET_DO_NOT_LEAK"
	if _, err := vaultwarden.Materialize(Request{Service: "passwords", Source: "services/passwords", Parameters: []string{"port=90000"}, SecretFile: "secrets/passwords.env"}); err == nil || !strings.Contains(err.Error(), "range 1-65535") {
		t.Fatalf("invalid port was accepted: %v", err)
	}
	if _, err := vaultwarden.Materialize(Request{Service: "passwords", Source: "services/passwords", Parameters: []string{"admin-token=" + sentinel}, SecretFile: "secrets/passwords.env"}); err == nil || !strings.Contains(err.Error(), "unknown parameter") {
		t.Fatalf("secret value parameter was accepted: %v", err)
	}
	materialization, err := vaultwarden.Materialize(Request{Service: "passwords", Source: "services/passwords", Parameters: []string{"domain=example.internal: {not-yaml}"}, SecretFile: "secrets/passwords.env"})
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(materialization.Compose)
	provenance, err := jsonBytes(materialization.Provenance)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, sentinel) || strings.Contains(string(provenance), sentinel) || !strings.Contains(encoded, "DOMAIN: \"example.internal: {not-yaml}\"") {
		t.Fatalf("parameter rendering leaked a secret or injected YAML structure:\n%s\n%s", encoded, provenance)
	}
	if string(materialization.SecretExample) != "ADMIN_TOKEN=\n" || materialization.Service.SecretEnvFile != "secrets/passwords.env" {
		t.Fatalf("secret scaffolding did not compile into M3 secret reference: %#v", materialization)
	}
}

func TestInitializeUpgradeAndEjectionBoundary(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "bebop.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	v1, err := catalog.Find("whoami", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	initial, err := v1.Materialize(Request{Service: "echo", Source: "services/echo", Parameters: []string{"port=8181"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(configPath, current, initial); err != nil {
		t.Fatal(err)
	}
	current, err = config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "services", "echo")
	provenance, err := LoadProvenance(filepath.Join(source, ProvenanceFilename))
	if err != nil {
		t.Fatal(err)
	}
	v2, err := catalog.Find("whoami", "1.1.0")
	if err != nil {
		t.Fatal(err)
	}
	input, err := v2.Reuse(provenance.Parameters, nil, provenance.SecretFile)
	if err != nil {
		t.Fatal(err)
	}
	next, err := v2.MaterializeWithInput(Request{Service: "echo", Source: "services/echo"}, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Upgrade(configPath, current, source, provenance, next); err != nil {
		t.Fatal(err)
	}
	updated, err := os.ReadFile(filepath.Join(source, ComposeFilename))
	if err != nil || !strings.Contains(string(updated), "bebop.recipe.revision") || !strings.Contains(string(updated), "8181:80") {
		t.Fatalf("compatible upgrade did not preserve typed value and update source: %s %v", updated, err)
	}
	if _, err := services.ResolveOne(current, "echo"); err != nil {
		t.Fatalf("recipe output is not an ordinary M3 service: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "manual.txt"), []byte("eject me"), 0o644); err != nil {
		t.Fatal(err)
	}
	updatedProvenance, err := LoadProvenance(filepath.Join(source, ProvenanceFilename))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Upgrade(configPath, current, source, updatedProvenance, next); err == nil || !strings.Contains(err.Error(), "diverged") {
		t.Fatalf("manual generated-source edit was silently overwritten: %v", err)
	}
	if err := os.Remove(filepath.Join(source, ProvenanceFilename)); err != nil {
		t.Fatal(err)
	}
	if _, err := services.ResolveOne(current, "echo"); err != nil {
		t.Fatalf("ejected service stopped being a normal Bebop service: %v", err)
	}
}

func TestUpgradeRejectsIncompatibleStoredParametersAndPersistentData(t *testing.T) {
	catalog, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	v1, err := catalog.Find("whoami", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	input, err := v1.Resolve([]string{"port=8181"}, "")
	if err != nil {
		t.Fatal(err)
	}
	next := v1
	next.Parameters[0].Type = "boolean"
	if _, err := next.Reuse(input.Values, nil, ""); err == nil || !strings.Contains(err.Error(), "boolean") {
		t.Fatalf("incompatible parameter type was reused: %v", err)
	}
	current := config.Service{Name: "echo", Type: "compose", Source: "services/echo", State: "running", HealthTimeout: "2m", Data: []config.DataResource{{Name: "app-data", Type: "volume", Volume: "data"}}, Backup: config.ServiceBackup{Consistency: "stop"}}
	changed := current
	changed.Data = append([]config.DataResource(nil), current.Data...)
	changed.Data[0].Name = "database-data"
	if sameServiceContract(current, changed) {
		t.Fatal("persistent logical-resource identity change was considered compatible")
	}
}

func TestSecretInitializationWritesOnlyTemplateReference(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "bebop.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := catalog.Find("vaultwarden", "")
	if err != nil {
		t.Fatal(err)
	}
	materialization, err := recipe.Materialize(Request{Service: "passwords", Source: "services/passwords", SecretFile: "secrets/passwords.env"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Initialize(configPath, current, materialization); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "secrets", "passwords.env")); !os.IsNotExist(err) {
		t.Fatalf("recipe init wrote deployable secret file: %v", err)
	}
	example, err := os.ReadFile(filepath.Join(root, "secrets", "passwords.env.example"))
	if err != nil || string(example) != "ADMIN_TOKEN=\n" {
		t.Fatalf("recipe init did not write clear secret template: %q %v", example, err)
	}
	provenance, err := os.ReadFile(filepath.Join(root, "services", "passwords", ProvenanceFilename))
	if err != nil || strings.Contains(string(provenance), "ADMIN_TOKEN=") {
		t.Fatalf("recipe provenance leaked secret content: %s %v", provenance, err)
	}
}

func jsonBytes(value any) ([]byte, error) { return json.Marshal(value) }
