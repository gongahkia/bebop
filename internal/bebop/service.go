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

func (s *Service) Inspect(ctx context.Context, t target.Target, dataRoot string) (facts.HostFacts, transport.Transport, error) {
	tr, err := s.Transport(t)
	if err != nil {
		return facts.HostFacts{}, nil, err
	}
	host, err := s.Inspector.Inspect(ctx, tr, t, dataRoot)
	return host, tr, err
}

func (s *Service) Plan(ctx context.Context, t target.Target, cfg config.Config) (facts.HostFacts, transport.Transport, plan.Plan, error) {
	host, tr, err := s.Inspect(ctx, t, cfg.Storage.DataRoot)
	if err != nil {
		return facts.HostFacts{}, nil, plan.Plan{}, err
	}
	result, err := s.Planner.Build(host, cfg)
	return host, tr, result, err
}
