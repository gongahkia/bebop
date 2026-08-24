package services

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
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

func TestResolveAllRejectsRelativeBindMounts(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", `services:
  hello:
    image: alpine:3.20
    volumes:
      - ./data:/data
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
	if _, err := ResolveAll(cfg); err == nil || !strings.Contains(err.Error(), "relative bind mount") {
		t.Fatalf("expected relative bind mount rejection, got %v", err)
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

func TestControlledArchiveContainsOnlySafeRegularRelativeEntries(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", "services:\n  hello:\n    image: alpine:3.20\n")
	writeFixture(t, root, "services/hello/nested/config.txt", "safe")
	writeFixture(t, root, "bebop.toml", `version = 1

[services.hello]
type = "compose"
source = "services/hello"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	reader := tar.NewReader(bytes.NewReader(deployment.Payload))
	entries := 0
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		entries++
		if filepath.IsAbs(header.Name) || strings.HasPrefix(filepath.Clean(header.Name), "..") || header.Typeflag != tar.TypeReg {
			t.Fatalf("unsafe controlled archive entry: %#v", header)
		}
	}
	if entries != 3 {
		t.Fatalf("unexpected archive entry count: %d", entries)
	}
}

func TestPersistentVolumeResolutionUsesLogicalComposeKeys(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", `services:
  hello:
    image: alpine:3.20
    volumes:
      - data:/var/lib/hello
      - type: volume
        source: external-data
        target: /external
volumes:
  data: {}
  external-data:
    external: true
    name: shared_hello_data
`)
	writeFixture(t, root, "bebop.toml", `version = 1

[server]
name = "destination"

[services.hello]
type = "compose"
source = "services/hello"

[[services.hello.data]]
name = "app-data"
type = "volume"
volume = "data"

[[services.hello.data]]
name = "external-data"
type = "volume"
volume = "external-data"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if len(deployment.Data) != 2 || deployment.Data[0].RuntimeVolume != deployment.Project+"_data" || !deployment.Data[1].External || deployment.Data[1].RuntimeVolume != "shared_hello_data" {
		t.Fatalf("logical volumes did not resolve safely: %#v", deployment.Data)
	}
	writeFixture(t, root, "bebop.toml", `version = 1
[services.hello]
type = "compose"
source = "services/hello"
[[services.hello.data]]
name = "missing"
type = "volume"
volume = "not-mounted"
`)
	cfg, err = config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveOne(cfg, "hello"); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("undeclared Compose volume was accepted: %v", err)
	}
}

func TestPersistentBindPathMustBeMountedByComposeService(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", `services:
  hello:
    image: alpine:3.20
    volumes:
      - /srv/hello/uploads:/uploads
`)
	writeFixture(t, root, "bebop.toml", `version = 1
[services.hello]
type = "compose"
source = "services/hello"
[[services.hello.data]]
name = "uploads"
type = "path"
path = "/srv/hello/uploads"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := ResolveOne(cfg, "hello")
	if err != nil || len(deployment.Data) != 1 || deployment.Data[0].Path != "/srv/hello/uploads" {
		t.Fatalf("mounted bind path was not resolved: %#v %v", deployment.Data, err)
	}
	writeFixture(t, root, "bebop.toml", `version = 1
[services.hello]
type = "compose"
source = "services/hello"
[[services.hello.data]]
name = "other"
type = "path"
path = "/srv/hello/other"
`)
	cfg, err = config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveOne(cfg, "hello"); err == nil || !strings.Contains(err.Error(), "not mounted") {
		t.Fatalf("undeclared Compose bind path was accepted: %v", err)
	}
}

func TestStorageRelativeBindPathUsesDeclaredComposeInterpolation(t *testing.T) {
	root := t.TempDir()
	writeFixture(t, root, "services/hello/compose.yaml", `services:
  hello:
    image: busybox:1.36.1
    volumes:
      - type: bind
        source: ${BEBOP_STORAGE_BULK}/media
        target: /data
`)
	writeFixture(t, root, "bebop.toml", `version = 1
[storage.resources.bulk]
mount = "/mnt/bulk"
filesystem_uuid = "11111111-2222-3333-4444-555555555555"
[services.hello]
type = "compose"
source = "services/hello"
[[services.hello.data]]
name = "media"
type = "path"
storage = "bulk"
path = "media"
`)
	cfg, err := config.LoadFile(filepath.Join(root, "bebop.toml"))
	if err != nil {
		t.Fatal(err)
	}
	deployment, err := ResolveOne(cfg, "hello")
	if err != nil {
		t.Fatal(err)
	}
	if got := deployment.Data[0].Path; got != "/mnt/bulk/media" {
		t.Fatalf("resolved storage path = %q", got)
	}
	if len(deployment.StorageEnvironment) != 1 || deployment.StorageEnvironment[0].Name != "BEBOP_STORAGE_BULK" {
		t.Fatalf("storage environment = %#v", deployment.StorageEnvironment)
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
