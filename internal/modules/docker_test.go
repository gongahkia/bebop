package modules

import (
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
)

func TestDockerPlansReviewedComposeCapabilityForServices(t *testing.T) {
	cfg := config.Defaults()
	cfg.Services = []config.Service{{Name: "hello", Type: "compose", Source: "services/hello", State: "running", HealthTimeout: config.DefaultServiceHealthTimeout}}
	host := facts.HostFacts{SudoAvailable: true, Docker: facts.Docker{Installed: true, ServiceEnabled: true, ServiceActive: true, Responsive: true, ComposePackageAvailable: "docker-compose-plugin"}}
	changes, _, err := (Docker{}).Plan(host, cfg)
	if err != nil || len(changes) != 1 || changes[0].ID != "docker.compose" || !strings.Contains(changes[0].Action.Script, "docker-compose-plugin") || changes[0].Blocked != "" {
		t.Fatalf("unexpected Compose install plan: %#v %v", changes, err)
	}
	host.Docker.ComposePackageAvailable = "untrusted-package"
	changes, _, err = (Docker{}).Plan(host, cfg)
	if err != nil || len(changes) != 1 || changes[0].Blocked == "" || changes[0].Action.Script != "" {
		t.Fatalf("unreviewed Compose package was not blocked: %#v %v", changes, err)
	}
}
