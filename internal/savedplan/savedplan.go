// Package savedplan validates a persistent plan against fresh facts before any
// mutation. It executes a freshly regenerated plan, never artifact scripts.
package savedplan

import (
	"context"
	"fmt"

	"github.com/bebop-home/bebop/internal/artifact"
	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

type Prepared struct {
	Target    target.Target
	Host      facts.HostFacts
	Transport transport.Transport
	Plan      plan.Plan
}

// Prepare closes the time between the saved-plan review and mutation: inspect,
// compare relevant state and identity, regenerate the plan, then return only
// that regenerated plan to the caller.
func Prepare(ctx context.Context, service *bebop.Service, saved artifact.Artifact, desired config.Config) (Prepared, error) {
	if err := saved.Verify(); err != nil {
		return Prepared{}, err
	}
	if err := ValidateConfig(saved, desired); err != nil {
		return Prepared{}, err
	}
	current, err := target.Parse(saved.Target)
	if err != nil {
		return Prepared{}, errs.New(errs.PlanInvalid, "saved plan target is invalid", err)
	}
	host, tr, err := service.Inspect(ctx, current, desired)
	if err != nil {
		return Prepared{}, err
	}
	fresh, err := ValidateObserved(saved, desired, host, service.Planner)
	if err != nil {
		return Prepared{}, err
	}
	return Prepared{Target: current, Host: host, Transport: tr, Plan: fresh}, nil
}

// ValidateObserved is pure once fresh facts exist, making the safety boundary
// directly testable without an SSH fixture.
func ValidateObserved(saved artifact.Artifact, desired config.Config, host facts.HostFacts, planner interface {
	Build(facts.HostFacts, config.Config) (plan.Plan, error)
}) (plan.Plan, error) {
	if err := saved.Verify(); err != nil {
		return plan.Plan{}, err
	}
	if err := ValidateConfig(saved, desired); err != nil {
		return plan.Plan{}, err
	}
	if !saved.HostIdentity.Matches(host.Identity()) {
		return plan.Plan{}, errs.New(errs.TargetIdentityMismatch, fmt.Sprintf("saved plan expects machine %s but target is %s", identityText(saved.HostIdentity), identityText(host.Identity())), nil)
	}
	currentObservedFingerprint, err := host.ConvergenceFingerprint()
	if err != nil {
		return plan.Plan{}, err
	}
	if currentObservedFingerprint != saved.ObservedStateFingerprint {
		return plan.Plan{}, errs.New(errs.PlanStale, "saved plan observed state changed; generate a new plan", nil)
	}
	fresh, err := planner.Build(host, desired)
	if err != nil {
		return plan.Plan{}, err
	}
	if fresh.Fingerprint != saved.Plan.Fingerprint {
		return plan.Plan{}, errs.New(errs.PlanStale, "fresh plan differs from the saved reviewed plan; generate a new plan", nil)
	}
	return fresh, nil
}

// ValidateConfig is intentionally called before reconnecting for saved-plan
// apply, so a changed local desired state cannot lead to any target operation.
func ValidateConfig(saved artifact.Artifact, desired config.Config) error {
	currentConfigFingerprint, err := config.Fingerprint(desired)
	if err != nil {
		return err
	}
	if currentConfigFingerprint != saved.ConfigFingerprint {
		return errs.New(errs.PlanStale, "saved plan configuration changed; generate a new plan", nil)
	}
	serviceInputsFingerprint, _, err := services.InputsFingerprint(desired)
	if err != nil {
		return err
	}
	if serviceInputsFingerprint != saved.ServiceInputsFingerprint {
		return errs.New(errs.PlanStale, "saved plan service source or secret input changed; generate a new plan", nil)
	}
	return nil
}

func identityText(identity facts.Identity) string {
	if identity.MachineID != "" {
		return identity.MachineID
	}
	return identity.Hostname + " (" + identity.OSID + " " + identity.OSVersion + ")"
}
