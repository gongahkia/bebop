//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDebianInspect runs only when explicitly requested through make
// test-integration. It compiles a static Linux controller binary and executes
// read-only inspect inside a disposable Debian container; it never calls apply.
func TestDebianInspect(t *testing.T) {
	if os.Getenv("BEBOP_INTEGRATION_DOCKER") != "1" {
		t.Skip("set BEBOP_INTEGRATION_DOCKER=1 to run against Docker")
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	binary := filepath.Join(t.TempDir(), "bebop")
	build := exec.Command("go", "build", "-o", binary, "./cmd/bebop")
	build.Dir = root
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux controller: %v\n%s", err, output)
	}
	command := exec.Command("docker", "run", "--rm", "--mount", "type=bind,src="+binary+",dst=/usr/local/bin/bebop,readonly", "debian:12", "/usr/local/bin/bebop", "inspect", "--target", "local", "--json")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run disposable Debian inspect: %v\n%s", err, output)
	}
	var result struct {
		OS struct {
			ID        string `json:"id"`
			Supported bool   `json:"supported"`
		} `json:"os"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode inspect JSON: %v\n%s", err, output)
	}
	if result.OS.ID != "debian" || !result.OS.Supported {
		t.Fatalf("unexpected Debian inspection: %#v", result.OS)
	}
}
