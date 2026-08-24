package modules

import (
	"context"
	"fmt"

	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

func runAction(ctx context.Context, tr transport.Transport, change plan.Change, allowed ...string) error {
	found := false
	for _, kind := range allowed {
		if change.Action.Kind == kind {
			found = true
			break
		}
	}
	if !found || change.Action.Script == "" {
		return fmt.Errorf("module refuses unexpected action %q", change.Action.Kind)
	}
	for _, precondition := range change.Preconditions {
		if precondition.ID == "" || precondition.Script == "" {
			return fmt.Errorf("module refuses invalid precondition for %q", change.ID)
		}
		if _, err := tr.Run(ctx, transport.Request{Script: precondition.Script, Privileged: change.RequiresRoot}); err != nil {
			return fmt.Errorf("precondition %s (%s) failed: %w", precondition.ID, precondition.Description, err)
		}
	}
	_, err := tr.Run(ctx, transport.Request{Script: change.Action.Script, Privileged: change.RequiresRoot})
	return err
}

func verify(ctx context.Context, tr transport.Transport, script string) error {
	_, err := tr.Run(ctx, transport.Request{Script: script, Privileged: true})
	return err
}

func rootBlocked(change *plan.Change, sudoAvailable bool) {
	if change.RequiresRoot && !sudoAvailable {
		change.Blocked = "non-interactive root access is unavailable; configure passwordless sudo for the target user or connect as root"
	}
}
