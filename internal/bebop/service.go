// Package bebop wires the application boundary without coupling CLI rendering to core semantics.
package bebop

import (
	"context"
	"fmt"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/inspect"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/services"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

type Service struct {
	Inspector        inspect.Inspector
	Planner          *planner.Planner
	TransportFactory func(target.Target) (transport.Transport, error)
}

func NewService() *Service { return &Service{Planner: planner.New(modules.Default()...)} }

func (s *Service) Transport(t target.Target) (transport.Transport, error) {
	if s.TransportFactory != nil {
		return s.TransportFactory(t)
	}
	switch t.Kind {
	case target.Local:
		return transport.NewLocal(), nil
	case target.SSH:
		return transport.NewSSH(t), nil
	default:
		return nil, fmt.Errorf("unsupported target transport %q", t.Kind)
	}
}

// Inspect validates local service inputs before contacting a target. This keeps
// malformed paths, source ambiguity, and port conflicts out of remote probes.
func (s *Service) Inspect(ctx context.Context, t target.Target, cfg config.Config) (facts.HostFacts, transport.Transport, error) {
	if _, err := services.ResolveAll(cfg); err != nil {
		return facts.HostFacts{}, nil, err
	}
	tr, err := s.Transport(t)
	if err != nil {
		return facts.HostFacts{}, nil, err
	}
	host, err := s.Inspector.Inspect(ctx, tr, t, cfg)
	return host, tr, err
}

func (s *Service) Plan(ctx context.Context, t target.Target, cfg config.Config) (facts.HostFacts, transport.Transport, plan.Plan, error) {
	host, tr, err := s.Inspect(ctx, t, cfg)
	if err != nil {
		return facts.HostFacts{}, nil, plan.Plan{}, err
	}
	result, err := s.Planner.Build(host, cfg)
	return host, tr, result, err
}
