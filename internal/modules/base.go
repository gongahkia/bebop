package modules

import (
	"context"
	"fmt"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Base struct{}

func (Base) Name() string { return "base" }

func (Base) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	root := cfg.Storage.DataRoot
	quoted := transport.ShellQuote(root)
	if !host.DataRoot.Exists {
		change := plan.Change{ID: "base.data-root", Module: "base", Summary: "create Bebop data root", Reason: fmt.Sprintf("%s does not exist", root), Risk: plan.Privileged, RequiresRoot: true, Current: "absent", Desired: "directory mode 0750 owned by root:root", Preconditions: []plan.Precondition{{ID: "base.data-root-absent", Description: "the configured data root is still absent", Script: "test ! -e -- " + quoted}}, Action: plan.Action{Kind: "base.create-data-root", Resource: root, Script: "install -d -m 0750 -o root -g root -- " + quoted}, Verification: "directory exists with mode 0750 and root ownership"}
		rootBlocked(&change, host.SudoAvailable)
		return []plan.Change{change}, nil, nil
	}
	if host.DataRoot.Mode != "750" || host.DataRoot.UID != 0 || host.DataRoot.GID != 0 {
		change := plan.Change{ID: "base.data-root.permissions", Module: "base", Summary: "correct Bebop data-root ownership and mode", Reason: "the configured Bebop-owned root does not match its declared permissions", Risk: plan.Privileged, RequiresRoot: true, Current: fmt.Sprintf("mode %s uid %d gid %d", host.DataRoot.Mode, host.DataRoot.UID, host.DataRoot.GID), Desired: "mode 0750 owned by root:root", Action: plan.Action{Kind: "base.set-data-root-permissions", Resource: root, Script: "chown root:root -- " + quoted + "\nchmod 0750 -- " + quoted}, Verification: "directory has mode 0750 and root ownership"}
		rootBlocked(&change, host.SudoAvailable)
		return []plan.Change{change}, nil, nil
	}
	return nil, nil, nil
}

func (Base) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "base.create-data-root", "base.set-data-root-permissions")
}

func (Base) Verify(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	root := transport.ShellQuote(change.Action.Resource)
	return verify(ctx, tr, "test -d -- "+root+"\ntest \"$(stat -c '%a:%u:%g' -- "+root+")\" = '750:0:0'")
}
