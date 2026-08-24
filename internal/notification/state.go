package notification

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/lease"
)

const StateSchemaVersion = 1
const DeliveryHistorySchemaVersion = 1

type Issue struct {
	Fingerprint   string          `json:"fingerprint"`
	Type          string          `json:"type"`
	Severity      Severity        `json:"severity"`
	Target        string          `json:"target"`
	Job           string          `json:"job,omitempty"`
	Service       string          `json:"service,omitempty"`
	Resource      string          `json:"resource,omitempty"`
	Summary       string          `json:"summary"`
	FirstSeen     time.Time       `json:"first_seen"`
	LastSeen      time.Time       `json:"last_seen"`
	RouteDelivery []RouteDelivery `json:"route_delivery,omitempty"`
}

type RouteDelivery struct {
	Route        string    `json:"route"`
	Delivered    bool      `json:"delivered"`
	LastNotified time.Time `json:"last_notified,omitempty"`
}

type stateFile struct {
	SchemaVersion int     `json:"schema_version"`
	Issues        []Issue `json:"issues"`
}

type DeliveryResult struct {
	SchemaVersion int       `json:"schema_version"`
	EventID       string    `json:"event_id"`
	Fingerprint   string    `json:"fingerprint"`
	Type          string    `json:"type"`
	Sink          string    `json:"sink"`
	Route         string    `json:"route,omitempty"`
	AttemptedAt   time.Time `json:"attempted_at"`
	Result        string    `json:"result"`
	Attempts      int       `json:"attempts,omitempty"`
	HTTPStatus    int       `json:"http_status,omitempty"`
	Category      string    `json:"category,omitempty"`
	Test          bool      `json:"test,omitempty"`
}

// Store owns only generated controller-local M8 state. Its existence never
// affects host, plan, backup, or maintenance-history correctness.
type Store struct {
	root       string
	maxEntries int
}

func OpenStore(cfg config.Config) (Store, error) {
	if cfg.Notifications == nil {
		return Store{}, fmt.Errorf("notification configuration is not declared")
	}
	if cfg.SourceDirectory() == "" {
		return Store{}, fmt.Errorf("notification state requires a file-backed configuration")
	}
	if err := config.ValidateNotifications(*cfg.Notifications); err != nil {
		return Store{}, err
	}
	root, err := localPath(cfg.SourceDirectory(), cfg.Notifications.StateDirectory)
	if err != nil {
		return Store{}, err
	}
	if err := ensureSafeDirectory(cfg.SourceDirectory(), cfg.Notifications.StateDirectory); err != nil {
		return Store{}, fmt.Errorf("prepare notification state directory: %w", err)
	}
	return Store{root: root, maxEntries: cfg.Notifications.HistoryMaxEntries}, nil
}

// ExistingStore returns a read-only view without creating state. It is used by
// notification status/list commands so inspection has no side effects.
func ExistingStore(cfg config.Config) (Store, error) {
	if cfg.Notifications == nil {
		return Store{}, fmt.Errorf("notification configuration is not declared")
	}
	if cfg.SourceDirectory() == "" {
		return Store{}, fmt.Errorf("notification state requires a file-backed configuration")
	}
	root, err := localPath(cfg.SourceDirectory(), cfg.Notifications.StateDirectory)
	if err != nil {
		return Store{}, err
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return Store{root: root, maxEntries: cfg.Notifications.HistoryMaxEntries}, nil
	}
	if err != nil {
		return Store{}, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return Store{}, fmt.Errorf("notification state directory must be a private real directory")
	}
	return Store{root: root, maxEntries: cfg.Notifications.HistoryMaxEntries}, nil
}

func (store Store) Root() string { return store.root }

func (store Store) statePath() string      { return filepath.Join(store.root, "state.json") }
func (store Store) lockPath() string       { return filepath.Join(store.root, ".state.lock") }
func (store Store) deliveriesPath() string { return filepath.Join(store.root, "deliveries") }

func (store Store) withLock(fn func(*stateFile) error) error {
	lock, err := lease.AcquireBlocking(store.lockPath())
	if err != nil {
		return fmt.Errorf("acquire notification state lock: %w", err)
	}
	defer lock.Release()
	state, err := store.load()
	if err != nil {
		return err
	}
	if err := fn(&state); err != nil {
		return err
	}
	return store.save(state)
}

func (store Store) load() (stateFile, error) {
	contents, err := os.ReadFile(store.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return stateFile{SchemaVersion: StateSchemaVersion}, nil
	}
	if err != nil {
		return stateFile{}, fmt.Errorf("read notification state: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(contents)))
	decoder.DisallowUnknownFields()
	var state stateFile
	if err := decoder.Decode(&state); err != nil {
		return stateFile{}, fmt.Errorf("notification state is corrupt: %w", err)
	}
	if state.SchemaVersion != StateSchemaVersion {
		return stateFile{}, fmt.Errorf("unsupported notification state schema version %d", state.SchemaVersion)
	}
	for _, issue := range state.Issues {
		if !validIssue(issue) {
			return stateFile{}, fmt.Errorf("notification state contains an invalid issue")
		}
	}
	sort.Slice(state.Issues, func(i, j int) bool { return state.Issues[i].Fingerprint < state.Issues[j].Fingerprint })
	return state, nil
}

func (store Store) save(state stateFile) error {
	state.SchemaVersion = StateSchemaVersion
	sort.Slice(state.Issues, func(i, j int) bool { return state.Issues[i].Fingerprint < state.Issues[j].Fingerprint })
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(store.statePath(), append(encoded, '\n'))
}

func (store Store) ActiveIssues() ([]Issue, error) {
	if _, err := os.Lstat(store.root); errors.Is(err, os.ErrNotExist) {
		return []Issue{}, nil
	}
	lock, err := lease.AcquireBlocking(store.lockPath())
	if err != nil {
		return nil, err
	}
	defer lock.Release()
	state, err := store.load()
	if err != nil {
		return nil, err
	}
	return append([]Issue{}, state.Issues...), nil
}

func (store Store) appendDelivery(result DeliveryResult) error {
	if !validDelivery(result) {
		return fmt.Errorf("invalid notification delivery record")
	}
	if err := os.MkdirAll(store.deliveriesPath(), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(store.deliveriesPath())
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("notification delivery history directory must be a private real directory")
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	filename := filepath.Join(store.deliveriesPath(), result.EventID+"-"+result.Sink+"-"+nonEmpty(result.Route, "test")+".json")
	if err := atomicWrite(filename, append(encoded, '\n')); err != nil {
		return err
	}
	return store.pruneDeliveries()
}

func (store Store) DeliveryHistory() ([]DeliveryResult, error) {
	directory := store.deliveriesPath()
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return []DeliveryResult{}, nil
	}
	if err != nil {
		return nil, err
	}
	result := make([]DeliveryResult, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !strings.HasPrefix(entry.Name(), "evt-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		contents, readErr := os.ReadFile(filepath.Join(directory, entry.Name()))
		if readErr != nil {
			continue
		}
		decoder := json.NewDecoder(strings.NewReader(string(contents)))
		decoder.DisallowUnknownFields()
		var delivery DeliveryResult
		if decoder.Decode(&delivery) != nil || !validDelivery(delivery) {
			continue
		}
		result = append(result, delivery)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].AttemptedAt.After(result[j].AttemptedAt) })
	return result, nil
}

func (store Store) pruneDeliveries() error {
	history, err := store.DeliveryHistory()
	if err != nil {
		return err
	}
	if len(history) <= store.maxEntries {
		return nil
	}
	for _, delivery := range history[store.maxEntries:] {
		filename := filepath.Join(store.deliveriesPath(), delivery.EventID+"-"+delivery.Sink+"-"+nonEmpty(delivery.Route, "test")+".json")
		if err := os.Remove(filename); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func validIssue(issue Issue) bool {
	return len(issue.Fingerprint) == 64 && issue.Type != "" && issue.Target != "" && issue.Summary != "" && !issue.FirstSeen.IsZero() && !issue.LastSeen.IsZero() && (issue.Severity == Warning || issue.Severity == Error || issue.Severity == Info)
}

func validDelivery(delivery DeliveryResult) bool {
	return delivery.SchemaVersion == DeliveryHistorySchemaVersion && validEventID(delivery.EventID) && len(delivery.Fingerprint) == 64 && delivery.Type != "" && validLocalName(delivery.Sink) && (delivery.Route == "" || validLocalName(delivery.Route)) && !delivery.AttemptedAt.IsZero() && (delivery.Result == "delivered" || delivery.Result == "failed" || delivery.Result == "suppressed")
}

func validEventID(value string) bool {
	return strings.HasPrefix(value, "evt-") && len(value) <= 128 && !strings.ContainsAny(value, "/\\\x00")
}
func validLocalName(value string) bool {
	if value == "" || len(value) > 63 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-') {
			return false
		}
	}
	return true
}

func localPath(base, value string) (string, error) {
	root := filepath.Join(base, filepath.FromSlash(value))
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(base, abs)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", fmt.Errorf("notification path escapes configuration directory")
	}
	return abs, nil
}

func ensureSafeDirectory(base, relative string) error {
	parts := strings.Split(filepath.Clean(filepath.FromSlash(relative)), string(filepath.Separator))
	current := base
	for _, part := range parts {
		if part == "." || part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("path component %s must be a private real directory", part)
		}
	}
	return nil
}

func atomicWrite(filename string, contents []byte) error {
	directory := filepath.Dir(filename)
	temporary, err := os.CreateTemp(directory, ".bebop-notification-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(contents); err != nil {
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
	return os.Rename(temporaryName, filename)
}
