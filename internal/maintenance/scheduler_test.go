package maintenance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSchedulerContextCapturesStableResolvedPaths(t *testing.T) {
	directory := t.TempDir()
	home := filepath.Join(directory, "home")
	project := filepath.Join(directory, "project")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(project, "bebop.toml")
	inventoryPath := filepath.Join(project, "hosts.toml")
	for _, filename := range []string{configPath, inventoryPath} {
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte("x"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	context, err := newSchedulerContext(configPath, inventoryPath, "/bin/sh", home, "darwin", 501)
	if err != nil {
		t.Fatal(err)
	}
	if context.ProjectRoot != project || context.ProjectID != SchedulerProjectID(project) || context.Platform != "darwin" || context.UID != 501 {
		t.Fatalf("unexpected scheduler context: %#v", context)
	}

	temporaryExecutable := filepath.Join(os.TempDir(), "bebop-transient-test")
	if err := os.WriteFile(temporaryExecutable, []byte("x"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(temporaryExecutable) })
	if _, err := newSchedulerContext(configPath, inventoryPath, temporaryExecutable, home, "darwin", 501); err == nil {
		t.Fatal("temporary scheduler executable was accepted")
	}
}
