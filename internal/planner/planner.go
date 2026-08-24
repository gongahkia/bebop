// Package planner turns normalized facts and a validated config into a plan.
package planner

import (
	"fmt"
	"sort"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/module"
	"github.com/bebop-home/bebop/internal/plan"
)

type Planner struct{ modules []module.Module }

func New(modules ...module.Module) *Planner {
	copyModules := append([]module.Module(nil), modules...)
	sort.Slice(copyModules, func(i, j int) bool { return copyModules[i].Name() < copyModules[j].Name() })
	return &Planner{modules: copyModules}
}

func (p *Planner) Modules() []module.Module { return append([]module.Module(nil), p.modules...) }

func (p *Planner) Build(host facts.HostFacts, cfg config.Config) (plan.Plan, error) {
	if err := config.Validate(cfg); err != nil {
		return plan.Plan{}, err
	}
	if !host.OS.Supported {
		return plan.Plan{}, errs.New(errs.UnsupportedOS, fmt.Sprintf("unsupported target OS %q; Bebop M0 supports Debian, Ubuntu, and Raspberry Pi OS", host.OS.ID), nil)
	}
	if !host.Systemd {
		return plan.Plan{}, errs.New(errs.UnsupportedOS, "supported Debian-family target does not expose systemd; Bebop M0 requires systemd", nil)
	}
	if host.PackageManager != "apt" {
		return plan.Plan{}, errs.New(errs.UnsupportedOS, "supported Debian-family target does not expose the required apt/dpkg package tools", nil)
	}
	result := plan.Plan{Version: 1, Target: host.Target}
	if !host.ArchitectureKnown {
		result.Warnings = append(result.Warnings, plan.Warning{ID: "host.architecture", Module: "host", Summary: "unknown target architecture: " + host.Architecture, Resolution: "Bebop will not infer architecture-specific packages; confirm repository availability before apply."})
	}
	if host.Firewall.UFWActive || host.Firewall.OtherActive {
		result.Warnings = append(result.Warnings, plan.Warning{ID: "firewall.external", Module: "firewall", Summary: "an existing firewall is active", Resolution: "Bebop M0 inspects firewall state but never modifies it."})
	}
	for _, current := range p.modules {
		changes, warnings, err := current.Plan(host, cfg)
		if err != nil {
			return plan.Plan{}, fmt.Errorf("plan %s: %w", current.Name(), err)
		}
		result.Changes = append(result.Changes, changes...)
		result.Warnings = append(result.Warnings, warnings...)
	}
	if err := result.Finalize(); err != nil {
		return plan.Plan{}, err
	}
	return result, nil
}
