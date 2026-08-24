package maintenance

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
)

// History stores immutable per-run JSON records. Per-run files avoid JSONL
// append races while remaining human-readable and portable between controllers.
type History struct {
	root       string
	maxEntries int
}

func NewHistory(cfg config.Config) (History, error) {
	root, err := HistoryRoot(cfg)
	if err != nil {
		return History{}, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return History{}, fmt.Errorf("create maintenance history: %w", err)
	}
	info, err := os.Lstat(root)
	if err != nil {
		return History{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return History{}, fmt.Errorf("maintenance history directory must be a real directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return History{}, fmt.Errorf("maintenance history directory must not be group- or world-writable")
	}
	return History{root: root, maxEntries: cfg.Maintenance.HistoryMaxEntries}, nil
}

// ExistingHistory opens history without creating controller state. Read-only
// status/show/history commands use it so declaring policy does not itself
// mutate the project.
func ExistingHistory(cfg config.Config) (History, error) {
	root, err := HistoryRoot(cfg)
	if err != nil {
		return History{}, err
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return History{root: root, maxEntries: cfg.Maintenance.HistoryMaxEntries}, nil
	}
	if err != nil {
		return History{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return History{}, fmt.Errorf("maintenance history directory must be a real directory")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return History{}, fmt.Errorf("maintenance history directory must not be group- or world-writable")
	}
	return History{root: root, maxEntries: cfg.Maintenance.HistoryMaxEntries}, nil
}

func HistoryRoot(cfg config.Config) (string, error) {
	if cfg.Maintenance == nil {
		return "", fmt.Errorf("maintenance configuration is not declared")
	}
	if cfg.SourceDirectory() == "" {
		return "", fmt.Errorf("maintenance history requires a file-backed configuration")
	}
	root := filepath.Join(cfg.SourceDirectory(), filepath.FromSlash(cfg.Maintenance.HistoryDirectory))
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(cfg.SourceDirectory(), abs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("maintenance history escapes configuration directory")
	}
	return abs, nil
}

func (history History) Append(record Record) error {
	if !validRecord(record) {
		return fmt.Errorf("invalid maintenance history record")
	}
	lock, err := AcquireFileLockBlocking(filepath.Join(history.root, ".history.lock"))
	if err != nil {
		return err
	}
	defer lock.Release()
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	filename := filepath.Join(history.root, record.RunID+".json")
	temporary, err := os.CreateTemp(history.root, ".bebop-history-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(append(encoded, '\n')); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, filename); err != nil {
		return err
	}
	return history.pruneLocked()
}

func (history History) List(job string) ([]Record, error) {
	entries, err := os.ReadDir(history.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]Record, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), "run-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(history.root, entry.Name()))
		if readErr != nil {
			continue
		}
		var record Record
		decoder := json.NewDecoder(strings.NewReader(string(contents)))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&record) != nil || !validRecord(record) || record.RunID+".json" != entry.Name() {
			continue
		}
		if job == "" || record.Job == job {
			result = append(result, record)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].StartedAt.Equal(result[j].StartedAt) {
			return result[i].RunID > result[j].RunID
		}
		return result[i].StartedAt.After(result[j].StartedAt)
	})
	return result, nil
}

func (history History) pruneLocked() error {
	records, err := history.List("")
	if err != nil {
		return err
	}
	if len(records) <= history.maxEntries {
		return nil
	}
	for _, record := range records[history.maxEntries:] {
		filename := filepath.Join(history.root, record.RunID+".json")
		if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func validRecord(record Record) bool {
	if record.SchemaVersion != HistorySchemaVersion || !validLocalID(record.RunID) || !validLocalID(record.Job) || len(record.JobFingerprint) != 64 || record.Operation == "" || record.Target == "" || (record.Origin != "manual" && record.Origin != "scheduled") || record.StartedAt.IsZero() || record.FinishedAt.IsZero() {
		return false
	}
	if record.Result != Success && record.Result != Warning && record.Result != Failure && record.Result != Skipped {
		return false
	}
	return true
}

func validLocalID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

func conciseError(err error) string {
	value := strings.Map(func(character rune) rune {
		if character < 0x20 || character == 0x7f {
			return ' '
		}
		return character
	}, err.Error())
	value = strings.TrimSpace(value)
	if len(value) > 500 {
		return value[:500]
	}
	return value
}
