package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
)

const testSecret = "BEBOP_TEST_SECRET_DO_NOT_LEAK"

func TestResolveAllIsDeterministicAndKeepsSecretOutOfInputs(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", `services:
  hello:
    image: alpine:3.20
    command: ["sleep", "infinity"]
    env_file: .bebop-secret.env
`)
	writeFixture(t, root, "services/hello/script.sh", "#!/bin/sh\necho hello\n")
	writeFixture(t, root, "secrets/hello.env", "TOKEN="+testSecret+"\n")
	configPath := filepath.Join(root, "bebop.toml")
	writeFixture(t, root, "bebop.toml", `version = 1

[server]
name = "home"

[services.hello]
type = "compose"
source = "services/hello"
secret_env_file = "secrets/hello.env"
`)
	cfg, err := config.LoadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ResolveAll(cfg)
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint, firstInputs, err := InputsFingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ResolveAll(cfg)
	if err != nil {
		t.Fatal(err)
	}
	secondFingerprint, secondInputs, err := InputsFingerprint(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].SourceDigest != second[0].SourceDigest || firstFingerprint != secondFingerprint {
		t.Fatalf("source resolution was not stable: %#v %#v", first, second)
	}
	firstJSON, _ := json.Marshal(firstInputs)
	secondJSON, _ := json.Marshal(secondInputs)
	if string(firstJSON) != string(secondJSON) || strings.Contains(string(firstJSON), testSecret) {
		t.Fatalf("secret leaked or inputs were unstable: %s / %s", firstJSON, secondJSON)
	}
	if !strings.Contains(string(first[0].Payload), testSecret) {
		t.Fatal("controlled transfer payload did not contain the configured secret")
	}
	if first[0].Files[1].Mode != "755" {
		t.Fatalf("executable bit was not normalized: %#v", first[0].Files)
	}
}

func TestResolveAllRejectsUnsafeSourcesAndPortConflicts(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/one/compose.yaml", `services:
  one:
    image: alpine:3.20
    ports: ["8080:80"]
`)
	writeFixture(t, root, "services/two/compose.yaml", `services:
  two:
    image: alpine:3.20
    ports: ["8080:80"]
`)
	writeFixture(t, root, "bebop.toml", `version = 1

[services.one]
type = "compose"
source = "services/one"

[services.two]
type = "compose"
source = "services/two"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAll(cfg); err == nil || !strings.Contains(err.Error(), "both declare host port") {
		t.Fatalf("expected deterministic port conflict, got %v", err)
	}
	writeFixture(t, root, "outside.txt", "outside")
	if err := os.Symlink(filepath.Join(root, "outside.txt"), filepath.Join(root, "services", "one", "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveOne(cfg, "one"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}

func TestResolveAllRejectsUnsupportedComposeFeatures(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", `services:
  hello:
    build: .
`)
	writeFixture(t, root, "bebop.toml", `version = 1

[services.hello]
type = "compose"
source = "services/hello"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAll(cfg); err == nil || !strings.Contains(err.Error(), "unsupported build") {
		t.Fatalf("expected build rejection, got %v", err)
	}
}

func TestAbsentServiceDoesNotRequireDeletedSource(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "bebop.toml", `version = 1

[services.hello]
type = "compose"
source = "services/removed"
state = "absent"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployments, err := ResolveAll(cfg)
	if err != nil || len(deployments) != 1 || deployments[0].SourceDigest != "" {
		t.Fatalf("absent service unexpectedly required a source: %#v %v", deployments, err)
	}
}

func writeFixture(t *testing.T, root, name, contents string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		t.Fatal(err)
	}
	mode := os.FileMode(0o644)
	if strings.HasSuffix(name, ".sh") {
		mode = 0o755
	}
	if err := os.WriteFile(filename, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
