// Package apply executes only reviewed plan actions and verifies each one.
package apply

import (
	"context"
	"errors"
	"fmt"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/module"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Result struct {
	Applied  []string  `json:"applied"`
	Verified []string  `json:"verified"`
	Final    plan.Plan `json:"final_plan"`
}

// Replan runs a complete fresh inspection and plan after actions complete.
// Apply never reads a saved plan from disk: the displayed plan is produced
// immediately before confirmation, which limits review-to-execution drift.
type Replan func(context.Context) (plan.Plan, error)

func Execute(ctx context.Context, reviewed plan.Plan, tr transport.Transport, desired config.Config, modules []module.Module, replan Replan) (Result, error) {
	for _, change := range reviewed.Changes {
		if change.Blocked != "" {
			return Result{}, errs.New(errs.PlanBlocked, fmt.Sprintf("change %s is blocked: %s", change.ID, change.Blocked), nil)
		}
	}
	var lock transport.ApplyLock
	if len(reviewed.Changes) > 0 {
		if locker, supported := tr.(transport.ApplyLocker); supported {
			acquired, err := locker.AcquireApplyLock(ctx)
			if err != nil {
				var lockError *transport.LockError
				if errors.As(err, &lockError) && lockError.Busy {
					return Result{}, errs.New(errs.ApplyLocked, lockError.Error(), err)
				}
				return Result{}, errs.New(errs.ApplyFailed, "acquire target apply lock", err)
			}
			lock = acquired
			defer lock.Release()
		}
	}
	byName := make(map[string]module.Module, len(modules))
	for _, candidate := range modules {
		byName[candidate.Name()] = candidate
	}
	result := Result{}
	for _, change := range reviewed.Changes {
		capability, found := byName[change.Module]
		if !found {
			return result, errs.New(errs.ApplyFailed, "plan references unavailable module "+change.Module, nil)
		}
		if err := capability.Apply(ctx, tr, desired, change); err != nil {
			return result, errs.New(errs.ApplyFailed, "apply "+change.ID, err)
		}
		result.Applied = append(result.Applied, change.ID)
		if err := capability.Verify(ctx, tr, desired, change); err != nil {
			return result, errs.New(errs.VerificationFailed, "verify "+change.ID, err)
		}
		result.Verified = append(result.Verified, change.ID)
	}
	final, err := replan(ctx)
	if err != nil {
		return result, errs.New(errs.VerificationFailed, "reinspect target after apply", err)
	}
	result.Final = final
	for _, change := range final.Changes {
		if change.Blocked == "" {
			return result, errs.New(errs.VerificationFailed, "target remains divergent after apply: "+change.ID, nil)
		}
	}
	return result, nil
}
