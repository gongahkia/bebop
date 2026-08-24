package artifact

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/target"
)

func testArtifact(t *testing.T) Artifact {
	t.Helper()
	current, err := target.Parse("ssh://pi@home")
	if err != nil {
		t.Fatal(err)
	}
	result := plan.Plan{Version: 1, Target: current.String(), Changes: []plan.Change{{
		ID: "docker.engine", Module: "docker", Summary: "install Docker", Risk: plan.Privileged,
		Current: "not installed", Desired: "installed", Preconditions: []plan.Precondition{{ID: "docker.absent", Description: "Docker remains absent", Script: "test true"}},
		Action: plan.Action{Kind: "docker.install-engine", Script: "apt-get install -y docker.io"}, Verification: "installed",
	}}}
	if err := result.Finalize(); err != nil {
		t.Fatal(err)
	}
	host := facts.HostFacts{Target: current.String(), Hostname: "pi", MachineID: "machine-a", OS: facts.OS{ID: "debian", VersionID: "12", Supported: true}, Architecture: "arm64", ArchitectureKnown: true, PackageManager: "apt", Systemd: true, SudoAvailable: true, DataRoot: facts.Directory{Path: "/srv/bebop"}}
	artifact, err := New("pi", "/work/hosts/pi.toml", current, config.Defaults(), host, result)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func TestArtifactIsCanonicalStableAndRoundTrips(t *testing.T) {
	artifact := testArtifact(t)
	first, err := artifact.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	second, err := artifact.CanonicalJSON()
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("artifact canonical form is unstable: %s %s %v", first, second, err)
	}
	path := filepath.Join(t.TempDir(), "plans", "pi.plan.json")
	if err := WriteFile(path, artifact); err != nil {
		t.Fatal(err)
	}
	firstFile, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, artifact); err != nil {
		t.Fatal(err)
	}
	secondFile, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(firstFile, secondFile) {
		t.Fatalf("artifact output changed between writes: %v", err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Fingerprint != artifact.Fingerprint || loaded.Plan.Changes[0].Risk != plan.Privileged || len(loaded.Plan.Changes[0].Preconditions) != 1 {
		t.Fatalf("artifact lost semantic plan data: %#v", loaded)
	}
}

func TestArtifactRejectsTamperAndUnsupportedSchema(t *testing.T) {
	artifact := testArtifact(t)
	artifact.Plan.Changes[0].Action.Script = "evil"
	if err := artifact.Verify(); !hasCode(err, errs.PlanTampered) {
		t.Fatalf("expected tamper rejection, got %v", err)
	}
	artifact = testArtifact(t)
	artifact.SchemaVersion = 2
	if err := artifact.Verify(); !hasCode(err, errs.PlanInvalid) {
		t.Fatalf("expected schema rejection, got %v", err)
	}
	if _, err := Decode(bytes.NewBufferString(`{"schema_version":1,"unknown":true}`)); !hasCode(err, errs.PlanInvalid) {
		t.Fatalf("expected malformed artifact rejection, got %v", err)
	}
}

func hasCode(err error, code errs.Code) bool {
	var categorized *errs.Error
	return errors.As(err, &categorized) && categorized.Code == code
}
