package bebop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/recipes"
)

func TestRecipeArchitectureGateBlocksBeforePlanning(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "bebop.toml")
	if err := os.WriteFile(configPath, []byte("version = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := recipes.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	recipe, err := catalog.Find("whoami", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	materialization, err := recipe.Materialize(recipes.Request{Service: "echo", Source: "services/echo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recipes.Initialize(configPath, current, materialization); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	err = recipeArchitectureError(cfg, "riscv64")
	var classified *errs.Error
	if !errors.As(err, &classified) || classified.Code != errs.PlanBlocked || !strings.Contains(err.Error(), "does not support target architecture riscv64") {
		t.Fatalf("recipe architecture was not a plan block: %v", err)
	}
}
