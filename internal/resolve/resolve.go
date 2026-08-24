// Package resolve maps a CLI target reference to the existing Target model.
package resolve

import (
	"fmt"
	"strings"

	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/target"
)

// Resolution keeps optional controller-side metadata next to the already
// established transport target. It does not introduce another execution path.
type Resolution struct {
	Alias         string
	Target        target.Target
	ConfigPath    string
	InventoryPath string
}

// Resolve accepts exactly one reference: a positional alias/literal target or
// --target. With neither, it preserves M0's local-target default.
func Resolve(reference, explicitTarget, inventoryPath string) (Resolution, error) {
	if reference != "" && explicitTarget != "" {
		return Resolution{}, errs.New(errs.TargetInvalid, "provide either a host reference or --target, not both", nil)
	}
	if explicitTarget != "" {
		parsed, err := target.Parse(explicitTarget)
		if err != nil {
			return Resolution{}, err
		}
		return Resolution{Target: parsed, InventoryPath: inventoryPath}, nil
	}
	if reference == "" {
		return Resolution{Target: target.Target{Kind: target.Local}, InventoryPath: inventoryPath}, nil
	}
	if reference == "local" || strings.Contains(reference, "://") {
		parsed, err := target.Parse(reference)
		if err != nil {
			return Resolution{}, err
		}
		return Resolution{Target: parsed, InventoryPath: inventoryPath}, nil
	}
	if err := inventory.ValidateAlias(reference); err != nil {
		return Resolution{}, err
	}
	loaded, err := inventory.LoadFile(inventoryPath)
	if err != nil {
		return Resolution{}, err
	}
	host, exists := loaded.Hosts[reference]
	if !exists {
		return Resolution{}, errs.New(errs.InventoryInvalid, fmt.Sprintf("unknown host alias %q in %s", reference, inventoryPath), nil)
	}
	parsed, err := target.Parse(host.Target)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{Alias: reference, Target: parsed, ConfigPath: inventory.ConfigPath(inventoryPath, host), InventoryPath: inventoryPath}, nil
}

func All(inventoryPath string) ([]Resolution, error) {
	loaded, err := inventory.LoadFile(inventoryPath)
	if err != nil {
		return nil, err
	}
	aliases := loaded.SortedAliases()
	result := make([]Resolution, 0, len(aliases))
	for _, alias := range aliases {
		host := loaded.Hosts[alias]
		parsed, err := target.Parse(host.Target)
		if err != nil {
			return nil, err
		}
		result = append(result, Resolution{Alias: alias, Target: parsed, ConfigPath: inventory.ConfigPath(inventoryPath, host), InventoryPath: inventoryPath})
	}
	return result, nil
}
