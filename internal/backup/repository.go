// Package backup owns controller-side, full-snapshot persistence artifacts.
// It deliberately has no network backend, scheduler, deduplication, or secret
// storage. Target streaming and service coordination live in operation.go.
package backup

import (
	"archive/tar"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
)

const (
	RepositorySchemaVersion = 1
	SnapshotSchemaVersion   = 1
	manifestFilename        = "manifest.json"
	snapshotsDirectory      = "snapshots"
	stagingDirectory        = ".staging"
)

// Repository is a controller-local filesystem repository. Root is resolved
// once and never stored in a snapshot manifest, preserving copied-repository
// portability.
type Repository struct{ root string }

type Source struct {
	HostAlias    string         `json:"host_alias,omitempty"`
	Target       string         `json:"target"`
	Identity     facts.Identity `json:"identity"`
	OS           facts.OS       `json:"os"`
	Architecture string         `json:"architecture,omitempty"`
}

type Manifest struct {
	SchemaVersion int               `json:"schema_version"`
	BebopVersion  string            `json:"bebop_version"`
	SnapshotID    string            `json:"snapshot_id"`
	CreatedAt     time.Time         `json:"created_at"`
	Source        Source            `json:"source"`
	Services      []ServiceManifest `json:"services"`
	Digest        string            `json:"digest"`
}

type ServiceManifest struct {
	Name                string             `json:"name"`
	ConfigurationDigest string             `json:"configuration_digest"`
	DeploymentDigest    string             `json:"deployment_digest,omitempty"`
	Consistency         string             `json:"consistency"`
	Resources           []ResourceManifest `json:"resources"`
}

type ResourceManifest struct {
	Name             string `json:"name"`
	Type             string `json:"type"`
	Archive          string `json:"archive"`
	UncompressedSize int64  `json:"uncompressed_size"`
	StoredSize       int64  `json:"stored_size"`
	SHA256           string `json:"sha256"`
}

type SnapshotSummary struct {
	SnapshotID string    `json:"snapshot_id"`
	CreatedAt  time.Time `json:"created_at"`
	HostAlias  string    `json:"host_alias,omitempty"`
	Target     string    `json:"target"`
	Services   []string  `json:"services"`
	StoredSize int64     `json:"stored_size"`
	Digest     string    `json:"digest"`
}

// Stage is private mutable state. It never appears in List until Complete
// writes/validates the manifest and atomically renames it into snapshots.
type Stage struct {
	repository Repository
	id         string
	path       string
	manifest   Manifest
	closed     bool
}

func (stage *Stage) child(parts ...string) (string, error) {
	joined := filepath.Join(append([]string{stage.path}, parts...)...)
	if !within(stage.path, joined) {
		return "", fmt.Errorf("backup staging path escapes snapshot")
	}
	return joined, nil
}

func Open(cfg config.Config) (Repository, error) {
	if err := config.Validate(cfg); err != nil {
		return Repository{}, err
	}
	destination := cfg.Backup.Destination
	if !filepath.IsAbs(destination) {
		if cfg.SourceDirectory() == "" {
			return Repository{}, errs.New(errs.ConfigInvalid, "relative backup.destination requires a configuration loaded from a file", nil)
		}
		destination = filepath.Join(cfg.SourceDirectory(), destination)
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return Repository{}, errs.New(errs.ConfigInvalid, "resolve backup destination", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return Repository{}, errs.New(errs.ConfigInvalid, "create backup destination", err)
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return Repository{}, errs.New(errs.ConfigInvalid, "inspect backup destination", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Repository{}, errs.New(errs.ConfigInvalid, "backup.destination must be a real directory", nil)
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return Repository{}, errs.New(errs.ConfigInvalid, "resolve backup destination", err)
	}
	for _, child := range []string{snapshotsDirectory, stagingDirectory} {
		if err := os.MkdirAll(filepath.Join(root, child), 0o700); err != nil {
			return Repository{}, errs.New(errs.ConfigInvalid, "prepare backup repository", err)
		}
	}
	return Repository{root: root}, nil
}

func (repository Repository) Root() string { return repository.root }

func (repository Repository) Begin(source Source, version string) (*Stage, error) {
	if repository.root == "" {
		return nil, errs.New(errs.ConfigInvalid, "backup repository is not initialized", nil)
	}
	id, err := newSnapshotID(time.Now().UTC())
	if err != nil {
		return nil, err
	}
	stagePath, err := repository.child(stagingDirectory, id)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(stagePath, 0o700); err != nil {
		return nil, errs.New(errs.ConfigInvalid, "create backup staging snapshot", err)
	}
	return &Stage{repository: repository, id: id, path: stagePath, manifest: Manifest{SchemaVersion: SnapshotSchemaVersion, BebopVersion: version, SnapshotID: id, CreatedAt: time.Now().UTC(), Source: source}}, nil
}

func (stage *Stage) ID() string { return stage.id }

func (stage *Stage) AddService(service ServiceManifest) error {
	if stage.closed {
		return fmt.Errorf("backup staging snapshot is closed")
	}
	if service.Name == "" || service.Consistency == "" || len(service.Resources) == 0 {
		return fmt.Errorf("invalid backup service manifest")
	}
	for _, existing := range stage.manifest.Services {
		if existing.Name == service.Name {
			return fmt.Errorf("duplicate backup service %q", service.Name)
		}
	}
	sort.Slice(service.Resources, func(i, j int) bool { return service.Resources[i].Name < service.Resources[j].Name })
	stage.manifest.Services = append(stage.manifest.Services, service)
	sort.Slice(stage.manifest.Services, func(i, j int) bool { return stage.manifest.Services[i].Name < stage.manifest.Services[j].Name })
	return nil
}

// WriteArchive sanitizes a target tar stream while writing it. This is both a
// streaming boundary and restore hardening: only regular files, directories,
// and safe relative symlinks survive into a completed snapshot.
func (stage *Stage) WriteArchive(ctx context.Context, relative string, input io.Reader) (ResourceManifest, error) {
	if stage.closed {
		return ResourceManifest{}, fmt.Errorf("backup staging snapshot is closed")
	}
	archivePath, err := safeArchivePath(relative)
	if err != nil {
		return ResourceManifest{}, errs.New(errs.ConfigInvalid, "unsafe backup archive path", err)
	}
	filename, err := stage.child(filepath.FromSlash(archivePath))
	if err != nil {
		return ResourceManifest{}, err
	}
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return ResourceManifest{}, err
	}
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ResourceManifest{}, err
	}
	defer file.Close()
	hash := sha256.New()
	count := &countWriter{writer: io.MultiWriter(file, hash)}
	if err := rewriteArchive(ctx, input, count); err != nil {
		return ResourceManifest{}, err
	}
	if err := file.Sync(); err != nil {
		return ResourceManifest{}, err
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	return ResourceManifest{Archive: archivePath, UncompressedSize: count.count, StoredSize: count.count, SHA256: digest}, nil
}

func (stage *Stage) Complete() (Manifest, error) {
	if stage.closed {
		return Manifest{}, fmt.Errorf("backup staging snapshot is closed")
	}
	stage.closed = true
	if len(stage.manifest.Services) == 0 {
		return Manifest{}, fmt.Errorf("backup snapshot contains no declared persistent resources")
	}
	if err := stage.manifest.Seal(); err != nil {
		return Manifest{}, err
	}
	encoded, err := json.MarshalIndent(stage.manifest, "", "  ")
	if err != nil {
		return Manifest{}, err
	}
	if err := os.WriteFile(filepath.Join(stage.path, manifestFilename), append(encoded, '\n'), 0o400); err != nil {
		return Manifest{}, err
	}
	if err := repositoryVerifyPath(stage.path, stage.manifest); err != nil {
		return Manifest{}, err
	}
	// Make archive and manifest contents immutable before publication. Directories
	// stay writable until after the rename so a failed publication remains staging.
	if err := setFilesReadOnly(stage.path); err != nil {
		return Manifest{}, errs.New(errs.VerificationFailed, "mark backup snapshot contents immutable", err)
	}
	completed, err := stage.repository.child(snapshotsDirectory, stage.id)
	if err != nil {
		return Manifest{}, err
	}
	if err := os.Rename(stage.path, completed); err != nil {
		return Manifest{}, errs.New(errs.ConfigInvalid, "publish completed backup snapshot", err)
	}
	if err := setDirectoriesReadOnly(completed); err != nil {
		// A snapshot whose final directory cannot be protected must not remain in
		// the completed namespace. Best-effort rollback leaves only recognizable
		// staging residue if moving it back succeeds.
		_ = setDirectoriesWritable(completed)
		_ = os.Rename(completed, stage.path)
		return Manifest{}, errs.New(errs.VerificationFailed, "mark completed backup snapshot immutable", err)
	}
	return stage.manifest, nil
}

func (stage *Stage) Abort() error {
	stage.closed = true
	return os.RemoveAll(stage.path)
}

func (repository Repository) Load(snapshotID string) (Manifest, error) {
	path, err := repository.snapshotPath(snapshotID)
	if err != nil {
		return Manifest{}, err
	}
	return loadManifest(path)
}

func (repository Repository) List() ([]SnapshotSummary, error) {
	directory, err := repository.child(snapshotsDirectory)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	result := make([]SnapshotSummary, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !validSnapshotID(entry.Name()) {
			continue
		}
		manifest, err := loadManifest(filepath.Join(directory, entry.Name()))
		if err != nil {
			continue // list reports completed, readable manifests only; verify names corruption explicitly.
		}
		summary := SnapshotSummary{SnapshotID: manifest.SnapshotID, CreatedAt: manifest.CreatedAt, HostAlias: manifest.Source.HostAlias, Target: manifest.Source.Target, Digest: manifest.Digest}
		for _, service := range manifest.Services {
			summary.Services = append(summary.Services, service.Name)
			for _, resource := range service.Resources {
				summary.StoredSize += resource.StoredSize
			}
		}
		result = append(result, summary)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].SnapshotID < result[j].SnapshotID })
	return result, nil
}

func (repository Repository) Verify(snapshotID string) (Manifest, error) {
	directory, err := repository.snapshotPath(snapshotID)
	if err != nil {
		return Manifest{}, err
	}
	manifest, err := loadManifest(directory)
	if err != nil {
		return Manifest{}, err
	}
	if err := repositoryVerifyPath(directory, manifest); err != nil {
		return Manifest{}, errs.New(errs.PlanTampered, "backup snapshot verification failed", err)
	}
	return manifest, nil
}

func (repository Repository) OpenArchive(snapshotID string, resource ResourceManifest) (*os.File, error) {
	directory, err := repository.snapshotPath(snapshotID)
	if err != nil {
		return nil, err
	}
	relative, err := safeArchivePath(resource.Archive)
	if err != nil {
		return nil, err
	}
	filename := filepath.Join(directory, filepath.FromSlash(relative))
	if !within(directory, filename) {
		return nil, fmt.Errorf("archive path escapes snapshot")
	}
	info, err := os.Lstat(filename)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("snapshot archive is not a regular file")
	}
	return os.Open(filename)
}

func (repository Repository) snapshotPath(snapshotID string) (string, error) {
	if !validSnapshotID(snapshotID) {
		return "", errs.New(errs.ConfigInvalid, "invalid snapshot identifier", nil)
	}
	return repository.child(snapshotsDirectory, snapshotID)
}

func (repository Repository) child(parts ...string) (string, error) {
	if repository.root == "" {
		return "", fmt.Errorf("backup repository is not initialized")
	}
	joined := filepath.Join(append([]string{repository.root}, parts...)...)
	if !within(repository.root, joined) {
		return "", fmt.Errorf("backup repository path escapes configured destination")
	}
	return joined, nil
}

func (manifest *Manifest) Seal() error {
	if err := validateManifest(*manifest); err != nil {
		return err
	}
	digest, err := manifestDigest(*manifest)
	if err != nil {
		return err
	}
	manifest.Digest = digest
	return nil
}

func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SnapshotSchemaVersion {
		return fmt.Errorf("unsupported backup snapshot schema version %d", manifest.SchemaVersion)
	}
	if !validSnapshotID(manifest.SnapshotID) || manifest.CreatedAt.IsZero() || manifest.BebopVersion == "" || manifest.Source.Target == "" {
		return fmt.Errorf("invalid backup snapshot manifest")
	}
	previousService := ""
	for _, service := range manifest.Services {
		if service.Name == "" || service.Name <= previousService || (service.Consistency != "stop" && service.Consistency != "live") {
			return fmt.Errorf("invalid backup service manifest")
		}
		previousService = service.Name
		previousResource := ""
		for _, resource := range service.Resources {
			if resource.Name == "" || resource.Name <= previousResource || (resource.Type != "volume" && resource.Type != "path") || resource.StoredSize < 0 || resource.UncompressedSize < 0 || len(resource.SHA256) != 64 {
				return fmt.Errorf("invalid backup resource manifest")
			}
			if _, err := hex.DecodeString(resource.SHA256); err != nil {
				return fmt.Errorf("invalid backup resource digest")
			}
			if _, err := safeArchivePath(resource.Archive); err != nil {
				return fmt.Errorf("invalid backup archive path: %w", err)
			}
			previousResource = resource.Name
		}
	}
	return nil
}

func manifestDigest(manifest Manifest) (string, error) {
	manifest.Digest = ""
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func loadManifest(directory string) (Manifest, error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return Manifest{}, errs.New(errs.ConfigInvalid, "backup snapshot does not exist", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Manifest{}, errs.New(errs.ConfigInvalid, "backup snapshot is not a real directory", nil)
	}
	contents, err := os.ReadFile(filepath.Join(directory, manifestFilename))
	if err != nil {
		return Manifest{}, errs.New(errs.ConfigInvalid, "read backup snapshot manifest", err)
	}
	var manifest Manifest
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, errs.New(errs.ConfigInvalid, "invalid backup snapshot manifest", err)
	}
	if err := validateManifest(manifest); err != nil {
		return Manifest{}, errs.New(errs.ConfigInvalid, "invalid backup snapshot manifest", err)
	}
	digest, err := manifestDigest(manifest)
	if err != nil || manifest.Digest != digest {
		return Manifest{}, errs.New(errs.PlanTampered, "backup manifest digest does not match", err)
	}
	return manifest, nil
}

func repositoryVerifyPath(directory string, manifest Manifest) error {
	if err := validateManifest(manifest); err != nil {
		return err
	}
	digest, err := manifestDigest(manifest)
	if err != nil || manifest.Digest != digest {
		return fmt.Errorf("manifest digest mismatch")
	}
	expected := map[string]ResourceManifest{}
	for _, service := range manifest.Services {
		for _, resource := range service.Resources {
			if _, exists := expected[resource.Archive]; exists {
				return fmt.Errorf("duplicate archive path")
			}
			expected[resource.Archive] = resource
		}
	}
	seen := map[string]bool{}
	err = filepath.WalkDir(directory, func(filename string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if filename == directory {
			return nil
		}
		relative, err := filepath.Rel(directory, filename)
		if err != nil {
			return err
		}
		logical := filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("snapshot contains symlink %q", logical)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("snapshot contains unsafe file %q", logical)
		}
		if logical == manifestFilename {
			return nil
		}
		resource, exists := expected[logical]
		if !exists {
			return fmt.Errorf("snapshot contains unexpected file %q", logical)
		}
		seen[logical] = true
		file, err := os.Open(filename)
		if err != nil {
			return err
		}
		hash := sha256.New()
		bytes, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if bytes != resource.StoredSize || hex.EncodeToString(hash.Sum(nil)) != resource.SHA256 {
			return fmt.Errorf("resource %q digest mismatch", resource.Name)
		}
		file, err = os.Open(filename)
		if err != nil {
			return err
		}
		archiveErr := validateArchive(context.Background(), file)
		_ = file.Close()
		return archiveErr
	})
	if err != nil {
		return err
	}
	for archive := range expected {
		if !seen[archive] {
			return fmt.Errorf("snapshot is missing archive %q", archive)
		}
	}
	return nil
}

func rewriteArchive(ctx context.Context, input io.Reader, output io.Writer) error {
	reader := tar.NewReader(input)
	writer := tar.NewWriter(output)
	seen := map[string]bool{}
	for entries := 0; ; entries++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if entries > 1_000_000 {
			return fmt.Errorf("archive contains too many entries")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read backup archive: %w", err)
		}
		clean, err := safeTarName(header.Name)
		if err != nil {
			return err
		}
		if seen[clean] {
			return fmt.Errorf("archive contains duplicate path %q", clean)
		}
		seen[clean] = true
		copyHeader, err := safeTarHeader(header, clean)
		if err != nil {
			return err
		}
		if err := writer.WriteHeader(copyHeader); err != nil {
			return err
		}
		if copyHeader.Typeflag == tar.TypeReg || copyHeader.Typeflag == tar.TypeRegA {
			if _, err := io.CopyBuffer(writer, reader, make([]byte, 128*1024)); err != nil {
				return err
			}
		}
	}
	return writer.Close()
}

func validateArchive(ctx context.Context, input io.Reader) error {
	return rewriteArchive(ctx, input, io.Discard)
}

func safeTarHeader(header *tar.Header, name string) (*tar.Header, error) {
	copyHeader := *header
	copyHeader.Name, copyHeader.PAXRecords, copyHeader.Xattrs = name, nil, nil
	copyHeader.Mode &= 0o777
	copyHeader.Devmajor, copyHeader.Devminor = 0, 0
	switch copyHeader.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		copyHeader.Linkname = ""
	case tar.TypeSymlink:
		if err := safeTarLink(name, copyHeader.Linkname); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("archive entry %q has unsupported type", name)
	}
	return &copyHeader, nil
}

func safeTarName(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') || strings.Contains(value, "\\") || path.IsAbs(value) {
		return "", fmt.Errorf("archive has unsafe path %q", value)
	}
	clean := path.Clean(value)
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("archive path escapes root: %q", value)
	}
	return clean, nil
}

func safeTarLink(name, link string) error {
	if link == "" || strings.ContainsRune(link, '\x00') || strings.Contains(link, "\\") || path.IsAbs(link) {
		return fmt.Errorf("archive symlink %q has unsafe target", name)
	}
	resolved := path.Clean(path.Join(path.Dir(name), link))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return fmt.Errorf("archive symlink %q escapes root", name)
	}
	return nil
}

func safeArchivePath(value string) (string, error) {
	if value == "" || strings.ContainsRune(value, '\x00') || strings.Contains(value, "\\") || path.IsAbs(value) {
		return "", fmt.Errorf("must be a relative archive path")
	}
	clean := path.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("archive path escapes snapshot")
	}
	return clean, nil
}

func within(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func validSnapshotID(value string) bool {
	if len(value) != len("20060102T150405Z-")+12 {
		return false
	}
	if _, err := time.Parse("20060102T150405Z", value[:16]); err != nil {
		return false
	}
	for _, character := range value[17:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return value[16] == '-'
}

func newSnapshotID(now time.Time) (string, error) {
	bytes := make([]byte, 6)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(bytes), nil
}

type countWriter struct {
	writer io.Writer
	count  int64
}

func (writer *countWriter) Write(contents []byte) (int, error) {
	count, err := writer.writer.Write(contents)
	writer.count += int64(count)
	return count, err
}

func setFilesReadOnly(root string) error {
	return filepath.Walk(root, func(filename string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		return os.Chmod(filename, 0o400)
	})
}

func setDirectoriesReadOnly(root string) error {
	return filepath.Walk(root, func(filename string, info fs.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return err
		}
		return os.Chmod(filename, 0o500)
	})
}

func setDirectoriesWritable(root string) error {
	return filepath.Walk(root, func(filename string, info fs.FileInfo, err error) error {
		if err != nil || !info.IsDir() {
			return err
		}
		return os.Chmod(filename, 0o700)
	})
}
