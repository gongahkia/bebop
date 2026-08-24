package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
)

func TestRepositoryPublishesOnlyVerifiedSnapshots(t *testing.T) {
	repository := testRepository(t)
	stage, err := repository.Begin(Source{Target: "local", Identity: facts.Identity{MachineID: "source"}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	const secretSentinel = "BEBOP_M4_SECRET_DO_NOT_RENDER"
	resource, err := stage.WriteArchive(context.Background(), "services/hello/data/app-data.tar", fixtureArchive(t, map[string]string{"state.txt": "portable state", "application-data.txt": secretSentinel}))
	if err != nil {
		t.Fatal(err)
	}
	resource.Name, resource.Type = "app-data", "volume"
	if err := stage.AddService(ServiceManifest{Name: "hello", ConfigurationDigest: strings.Repeat("a", 64), Consistency: "stop", Resources: []ResourceManifest{resource}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := stage.Complete()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Verify(manifest.SnapshotID); err != nil {
		t.Fatal(err)
	}
	listed, err := repository.List()
	if err != nil || len(listed) != 1 || listed[0].SnapshotID != manifest.SnapshotID {
		t.Fatalf("unexpected completed snapshots: %#v %v", listed, err)
	}
	if manifest.Digest == "" || manifest.Services[0].Resources[0].SHA256 == "" {
		t.Fatalf("missing snapshot integrity metadata: %#v", manifest)
	}
	encoded, err := os.ReadFile(filepath.Join(repository.Root(), snapshotsDirectory, manifest.SnapshotID, manifestFilename))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secretSentinel) {
		t.Fatalf("snapshot manifest leaked resource contents: %s", encoded)
	}
}

func TestRepositoryRejectsCorruptAndUnsafeArchives(t *testing.T) {
	repository := testRepository(t)
	stage, err := repository.Begin(Source{Target: "local"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.WriteArchive(context.Background(), "services/hello/data/app.tar", fixtureArchive(t, map[string]string{"../../escape": "bad"})); err == nil {
		t.Fatal("unsafe archive was accepted")
	}
	if err := stage.Abort(); err != nil {
		t.Fatal(err)
	}
	if listed, err := repository.List(); err != nil || len(listed) != 0 {
		t.Fatalf("partial snapshot was listed: %#v %v", listed, err)
	}

	stage, err = repository.Begin(Source{Target: "local"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	resource, err := stage.WriteArchive(context.Background(), "services/hello/data/app.tar", fixtureArchive(t, map[string]string{"ok": "good"}))
	if err != nil {
		t.Fatal(err)
	}
	resource.Name, resource.Type = "app", "volume"
	if err := stage.AddService(ServiceManifest{Name: "hello", ConfigurationDigest: strings.Repeat("b", 64), Consistency: "stop", Resources: []ResourceManifest{resource}}); err != nil {
		t.Fatal(err)
	}
	manifest, err := stage.Complete()
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(repository.Root(), snapshotsDirectory, manifest.SnapshotID, filepath.FromSlash(resource.Archive))
	if err := os.Chmod(archive, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(archive, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("tamper")); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Verify(manifest.SnapshotID); err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("corrupt snapshot verified: %v", err)
	}
	if _, err := repository.OpenArchive("../../etc", resource); err == nil {
		t.Fatal("path-injected snapshot ID accepted")
	}
}

func TestRepositoryRejectsArchiveLinkEscapesAndHardLinks(t *testing.T) {
	repository := testRepository(t)
	for name, header := range map[string]*tar.Header{
		"link escape": {Name: "data/link", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"},
		"hard link":   {Name: "data/hard", Typeflag: tar.TypeLink, Linkname: "data/file"},
	} {
		t.Run(name, func(t *testing.T) {
			stage, err := repository.Begin(Source{Target: "local"}, "test")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := stage.WriteArchive(context.Background(), "services/hello/data/app.tar", archiveWithHeader(t, header)); err == nil {
				t.Fatal("unsafe link archive was accepted")
			}
			if err := stage.Abort(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRepositoryCanonicalManifestAndStreamingArchive(t *testing.T) {
	manifest := Manifest{
		SchemaVersion: SnapshotSchemaVersion,
		BebopVersion:  "test",
		SnapshotID:    "20260824T041500Z-0123456789ab",
		CreatedAt:     time.Date(2026, 8, 24, 4, 15, 0, 0, time.UTC),
		Source:        Source{Target: "local"},
		Services: []ServiceManifest{{
			Name: "hello", ConfigurationDigest: strings.Repeat("c", 64), Consistency: "live",
			Resources: []ResourceManifest{{Name: "data", Type: "volume", Archive: "services/hello/data/data.tar", SHA256: strings.Repeat("d", 64)}},
		}},
	}
	first := manifest
	second := manifest
	if err := first.Seal(); err != nil {
		t.Fatal(err)
	}
	if err := second.Seal(); err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest {
		t.Fatalf("manifest digest is nondeterministic: %s / %s", first.Digest, second.Digest)
	}

	contents := strings.Repeat("x", 2<<20)
	archive := fixtureArchive(t, map[string]string{"large": contents})
	reader := &limitedReader{reader: archive, maximum: 0}
	if err := validateArchive(context.Background(), reader); err != nil {
		t.Fatal(err)
	}
	if reader.maximum > 128*1024 {
		t.Fatalf("archive reader was asked for an unbounded buffer: %d", reader.maximum)
	}
}

func testRepository(t *testing.T) Repository {
	t.Helper()
	root := t.TempDir()
	cfg := config.WithSourceDirectory(config.Defaults(), root)
	cfg.Backup.Destination = "backups"
	repository, err := Open(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = filepath.Walk(repository.Root(), func(filename string, info os.FileInfo, err error) error {
			if err == nil {
				_ = os.Chmod(filename, 0o700)
			}
			return nil
		})
	})
	return repository
}

func fixtureArchive(t *testing.T, files map[string]string) io.Reader {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	for name, contents := range files {
		if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o640, Size: int64(len(contents)), Format: tar.FormatUSTAR}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(output.Bytes())
}

func archiveWithHeader(t *testing.T, header *tar.Header) io.Reader {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(output.Bytes())
}

type limitedReader struct {
	reader  io.Reader
	maximum int
}

func (reader *limitedReader) Read(buffer []byte) (int, error) {
	if len(buffer) > reader.maximum {
		reader.maximum = len(buffer)
	}
	return reader.reader.Read(buffer)
}
