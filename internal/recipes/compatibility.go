package recipes

import (
	"os"
	"path/filepath"

	"github.com/bebop-home/bebop/internal/config"
)

// ManagedService is a best-effort controller-side association between ordinary
// service source and valid provenance. Missing or malformed provenance is not a
// generic-service error: deleting it is the documented recipe ejection path.
type ManagedService struct {
	Service    config.Service
	Recipe     Recipe
	Provenance Provenance
}

func Managed(cfg config.Config) ([]ManagedService, error) {
	if cfg.SourceDirectory() == "" {
		return nil, nil
	}
	catalog, err := Builtin()
	if err != nil {
		return nil, err
	}
	result := make([]ManagedService, 0)
	for _, service := range cfg.Services {
		filename := filepath.Join(cfg.SourceDirectory(), filepath.FromSlash(service.Source), ProvenanceFilename)
		if _, err := os.Lstat(filename); os.IsNotExist(err) {
			continue
		} else if err != nil {
			continue
		}
		provenance, err := LoadProvenance(filename)
		if err != nil || provenance.Source != service.Source {
			continue
		}
		recipe, err := catalog.Find(provenance.RecipeID, provenance.RecipeVersion)
		if err != nil || recipe.Fingerprint != provenance.RecipeFingerprint {
			continue
		}
		result = append(result, ManagedService{Service: service, Recipe: recipe, Provenance: provenance})
	}
	return result, nil
}

// Incompatible returns valid recipe-managed services unsupported by a target
// architecture. Generic services and deliberately ejected sources are omitted.
func Incompatible(cfg config.Config, architecture string) ([]ManagedService, error) {
	managed, err := Managed(cfg)
	if err != nil {
		return nil, err
	}
	result := make([]ManagedService, 0)
	for _, service := range managed {
		if !service.Recipe.SupportsArchitecture(architecture) {
			result = append(result, service)
		}
	}
	return result, nil
}
