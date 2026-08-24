package preflight

import (
	"errors"
	"testing"

	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

func TestFromFactsSeparatesReadinessFailuresFromOperationalWarnings(t *testing.T) {
	host := facts.HostFacts{
		Target:            "ssh://pi@home",
		OS:                facts.OS{ID: "debian", Name: "Debian", VersionID: "12", Supported: true},
		Architecture:      "arm64",
		ArchitectureKnown: true,
		PackageManager:    "apt",
		Systemd:           true,
		SudoAvailable:     true,
		DataRoot:          facts.Directory{Path: "/srv/bebop"},
	}
	result := FromFacts(target.Target{Kind: target.SSH, User: "pi", Host: "home"}, host)
	if !result.Ready || !result.Reachable || !result.Authenticated {
		t.Fatalf("supported host should be ready: %#v", result)
	}
	if len(result.Checks) == 0 || result.Checks[len(result.Checks)-1].Status != Warn {
		t.Fatalf("expected non-blocking operational warnings: %#v", result.Checks)
	}
	host.PackageManager = "unknown"
	blocked := FromFacts(target.Target{Kind: target.Local}, host)
	if blocked.Ready || blocked.FailureError() == nil {
		t.Fatalf("missing apt should block readiness: %#v", blocked)
	}
}

func TestFailureClassificationProducesActionableResult(t *testing.T) {
	result := unavailable(Result{Target: "ssh://pi@home"}, transport.ClassifyFailure(errors.New("Host key verification failed")), "SSH host-key verification failed")
	if result.Ready || result.Failure != transport.FailureHostKey || result.FailureError() == nil {
		t.Fatalf("unexpected unavailable result: %#v", result)
	}
}
