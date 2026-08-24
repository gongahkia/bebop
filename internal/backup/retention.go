package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// RetentionPlan is a deterministic, auditable selection. It is limited to
// verified snapshots carrying exactly the requested maintenance provenance.
type RetentionPlan struct {
	Scope          string            `json:"scope"`
	KeepLast       int               `json:"keep_last"`
	Remove         []SnapshotSummary `json:"remove"`
	CorruptSkipped []string          `json:"corrupt_skipped,omitempty"`
}

// PlanRetention selects oldest verified snapshots after stable ordering by
// creation time and snapshot ID. Manual snapshots and snapshots from other
// jobs/scopes are never candidates.
func (repository Repository) PlanRetention(scope string, keepLast int) (RetentionPlan, error) {
	if len(scope) != 64 || keepLast < 1 {
		return RetentionPlan{}, fmt.Errorf("invalid backup retention policy")
	}
	directory, err := repository.child(snapshotsDirectory)
	if err != nil {
		return RetentionPlan{}, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return RetentionPlan{}, err
	}
	plan := RetentionPlan{Scope: scope, KeepLast: keepLast}
	candidates := make([]SnapshotSummary, 0)
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !validSnapshotID(entry.Name()) {
			continue
		}
		manifest, loadErr := loadManifest(filepath.Join(directory, entry.Name()))
		if loadErr != nil || manifest.Maintenance == nil || manifest.Maintenance.Scope != scope {
			continue
		}
		if _, verifyErr := repository.Verify(manifest.SnapshotID); verifyErr != nil {
			plan.CorruptSkipped = append(plan.CorruptSkipped, manifest.SnapshotID)
			continue
		}
		summary := SnapshotSummary{SnapshotID: manifest.SnapshotID, CreatedAt: manifest.CreatedAt, HostAlias: manifest.Source.HostAlias, Target: manifest.Source.Target, Digest: manifest.Digest}
		for _, service := range manifest.Services {
			summary.Services = append(summary.Services, service.Name)
			for _, resource := range service.Resources {
				summary.StoredSize += resource.StoredSize
			}
		}
		candidates = append(candidates, summary)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt.Equal(candidates[j].CreatedAt) {
			return candidates[i].SnapshotID < candidates[j].SnapshotID
		}
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	sort.Strings(plan.CorruptSkipped)
	if len(candidates) > keepLast {
		plan.Remove = append(plan.Remove, candidates[:len(candidates)-keepLast]...)
	}
	return plan, nil
}

// ApplyRetention delegates every deletion to Repository.Delete so retention
// cannot acquire an unsafe raw filesystem deletion path.
func (repository Repository) ApplyRetention(plan RetentionPlan) error {
	for _, snapshot := range plan.Remove {
		if err := repository.Delete(snapshot.SnapshotID); err != nil {
			return err
		}
	}
	return nil
}
