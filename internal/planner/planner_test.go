package planner_test

import (
	"context"
	"testing"

	"github.com/bebop-home/bebop/internal/apply"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/module"
	"github.com/bebop-home/bebop/internal/modules"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/planner"
	"github.com/bebop-home/bebop/internal/transport"
)

func initialFacts() facts.HostFacts {
	return facts.HostFacts{Target: "ssh://pi@home", OS: facts.OS{ID: "raspbian", Name: "Raspberry Pi OS", VersionID: "12", VersionCodename: "bookworm", Family: "raspberry-pi-os", Supported: true}, Architecture: "arm64", ArchitectureKnown: true, PackageManager: "apt", InitSystem: "systemd", Systemd: true, EffectiveUser: "pi", SudoAvailable: true, SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, AuthorizedKeysPresent: true}, DataRoot: facts.Directory{Path: config.DefaultDataRoot}}
}

func TestPlanIsCanonicalAndIdempotentAfterTransitions(t *testing.T) {
	p := planner.New(modules.Default()...)
	cfg := config.Defaults()
	host := initialFacts()
	first, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := first.CanonicalJSON()
	secondJSON, _ := second.CanonicalJSON()
	if string(firstJSON) != string(secondJSON) || first.Fingerprint != second.Fingerprint {
		t.Fatalf("plan was not deterministic\n%s\n%s", firstJSON, secondJSON)
	}
	if len(first.Changes) != 7 {
		t.Fatalf("expected seven changes, got %d: %#v", len(first.Changes), first.Changes)
	}
	transition(&host, first)
	converged, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(converged.Changes) != 0 {
		t.Fatalf("expected no changes after transition: %#v", converged.Changes)
	}
}

func TestApplyUsesPlanAndSecondApplyDoesNothing(t *testing.T) {
	p := planner.New(modules.Default()...)
	cfg := config.Defaults()
	host := initialFacts()
	reviewed, err := p.Build(host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr := &recordingTransport{}
	result, err := apply.Execute(context.Background(), reviewed, tr, p.Modules(), func(context.Context) (plan.Plan, error) { transition(&host, reviewed); return p.Build(host, cfg) })
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Verified) != len(reviewed.Changes) || tr.mutations != len(reviewed.Changes)+len(reviewed.Changes) {
		t.Fatalf("apply/verify mismatch: %#v mutations=%d", result, tr.mutations)
	}
	before := tr.mutations
	if _, err := apply.Execute(context.Background(), result.Final, tr, p.Modules(), func(context.Context) (plan.Plan, error) { return result.Final, nil }); err != nil {
		t.Fatal(err)
	}
	if tr.mutations != before {
		t.Fatalf("second apply made operations: %d -> %d", before, tr.mutations)
	}
}

func transition(host *facts.HostFacts, result plan.Plan) {
	for _, change := range result.Changes {
		switch change.ID {
		case "base.data-root", "base.data-root.permissions":
			host.DataRoot.Exists = true
			host.DataRoot.Mode = "750"
			host.DataRoot.UID, host.DataRoot.GID = 0, 0
		case "updates.unattended":
			host.AutomaticUpdates = facts.AutomaticUpdates{Installed: true, Enabled: true}
		case "docker.engine":
			host.Docker.Installed = true
		case "docker.service":
			host.Docker.ServiceEnabled, host.Docker.ServiceActive, host.Docker.Responsive = true, true, true
		case "tailscale.package":
			host.Tailscale.Installed = true
		case "tailscale.service":
			host.Tailscale.ServiceEnabled, host.Tailscale.ServiceActive = true, true
		case "ssh.hardening":
			host.SSH.BebopDropIn = modules.SSHDropIn
		}
	}
}

type recordingTransport struct{ mutations int }

func (r *recordingTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	r.mutations++
	return transport.Result{}, nil
}
func (r *recordingTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (r *recordingTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (r *recordingTransport) Description() string                              { return "recording" }

var _ module.Module = modules.Base{}
