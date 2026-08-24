package apply

import (
	"context"
	"errors"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/module"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestVerificationFailureDoesNotReportConvergence(t *testing.T) {
	capability := failingModule{}
	replanCalls := 0
	reviewed := plan.Plan{Changes: []plan.Change{{ID: "test.change", Module: "test", Action: plan.Action{Kind: "test.action", Script: "false"}}}}
	_, err := Execute(context.Background(), reviewed, &noopTransport{}, config.Defaults(), []module.Module{capability}, func(context.Context) (plan.Plan, error) {
		replanCalls++
		return plan.Plan{}, nil
	})
	if err == nil || replanCalls != 0 {
		t.Fatalf("verification failure must stop before convergence replan: err=%v calls=%d", err, replanCalls)
	}
}

func TestBusyApplyLockPreventsAnyModuleExecution(t *testing.T) {
	capability := &countingModule{}
	locked := &busyLockTransport{}
	reviewed := plan.Plan{Changes: []plan.Change{{ID: "test.change", Module: "test", Action: plan.Action{Kind: "test.action", Script: "true"}}}}
	_, err := Execute(context.Background(), reviewed, locked, config.Defaults(), []module.Module{capability}, func(context.Context) (plan.Plan, error) { return plan.Plan{}, nil })
	var categorized *errs.Error
	if !errors.As(err, &categorized) || categorized.Code != errs.ApplyLocked || capability.applied {
		t.Fatalf("busy lock did not stop apply before mutation: err=%v applied=%t", err, capability.applied)
	}
}

type failingModule struct{}

func (failingModule) Name() string { return "test" }
func (failingModule) Plan(facts.HostFacts, config.Config) ([]plan.Change, []plan.Warning, error) {
	return nil, nil, nil
}
func (failingModule) Apply(context.Context, transport.Transport, config.Config, plan.Change) error {
	return nil
}
func (failingModule) Verify(context.Context, transport.Transport, config.Config, plan.Change) error {
	return errors.New("candidate validation failed")
}

type noopTransport struct{}

func (*noopTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	return transport.Result{}, nil
}
func (*noopTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (*noopTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (*noopTransport) Description() string                              { return "noop" }

type busyLockTransport struct{ noopTransport }

func (*busyLockTransport) AcquireApplyLock(context.Context) (transport.ApplyLock, error) {
	return nil, &transport.LockError{Busy: true}
}

type countingModule struct{ applied bool }

func (module countingModule) Name() string { return "test" }
func (module countingModule) Plan(facts.HostFacts, config.Config) ([]plan.Change, []plan.Warning, error) {
	return nil, nil, nil
}
func (module *countingModule) Apply(context.Context, transport.Transport, config.Config, plan.Change) error {
	module.applied = true
	return nil
}
func (module countingModule) Verify(context.Context, transport.Transport, config.Config, plan.Change) error {
	return nil
}
