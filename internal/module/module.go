// Package module specifies the capability boundary used by the planner and apply engine.
package module

import (
	"context"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/transport"
)

type Module interface {
	Name() string
	Plan(facts.HostFacts, config.Config) ([]plan.Change, []plan.Warning, error)
	Apply(context.Context, transport.Transport, plan.Change) error
	Verify(context.Context, transport.Transport, plan.Change) error
}
