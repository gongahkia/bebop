//go:build darwin && integration

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLaunchdLifecycleAgainstUserDomain is deliberately opt-in. It installs a
// project-unique LaunchAgent in the logged-in user's gui domain, verifies
// Bebop's semantic status, then removes that exact owned artifact. A stable
// installed binary is required because the generated plist must not capture a
// transient `go test` or `go run` executable.
func TestLaunchdLifecycleAgainstUserDomain(t *testing.T) {
	if os.Getenv("BEBOP_LAUNCHD_INTEGRATION") != "1" {
		t.Skip("set BEBOP_LAUNCHD_INTEGRATION=1 and BEBOP_LAUNCHD_BINARY to run against the current macOS user launchd domain")
	}
	binary := os.Getenv("BEBOP_LAUNCHD_BINARY")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("BEBOP_LAUNCHD_BINARY must be an absolute path to a stable installed Bebop binary")
	}
	binary, err := filepath.EvalSymlinks(binary)
	if err != nil {
		t.Fatalf("resolve BEBOP_LAUNCHD_BINARY: %v", err)
	}
	if temporary, tempErr := filepath.Abs(os.TempDir()); tempErr == nil {
		if relative, relativeErr := filepath.Rel(temporary, binary); relativeErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative) {
			t.Fatal("BEBOP_LAUNCHD_BINARY must not be under the temporary directory")
		}
	}
	project := t.TempDir()
	config := filepath.Join(project, "bebop.toml")
	if err := os.WriteFile(config, []byte(`version = 1

[maintenance]
version = 1

[[maintenance.jobs]]
name = "launchd-smoke"
type = "doctor"
target = "local"
schedule = "daily@03:00"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	inventory := filepath.Join(project, "bebop.hosts.toml")
	cleanup := func() {
		_ = exec.Command(binary, "maintenance", "uninstall", "--yes", "--config", config, "--inventory", inventory).Run()
	}
	t.Cleanup(cleanup)
	command := exec.Command(binary, "maintenance", "install", "--config", config, "--inventory", inventory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("maintenance install: %v\n%s", err, output)
	}
	command = exec.Command(binary, "maintenance", "status", "--config", config, "--inventory", inventory, "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("maintenance status: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), `"backend":"launchd"`) || !strings.Contains(string(output), `"state":"current"`) {
		t.Fatalf("launchd status did not report a current adapter artifact: %s", output)
	}
	cleanup()
}
