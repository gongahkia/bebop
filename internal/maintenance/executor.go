package maintenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/backup"
	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/preflight"
	"github.com/bebop-home/bebop/internal/resolve"
	"github.com/bebop-home/bebop/internal/transport"
)

// BebopExecutor is the sole M7 adapter into existing operation layers. It
// does not start another Bebop process or reimplement transport, locking,
// backup, doctor, or service lifecycle behavior.
type BebopExecutor struct {
	Service          *bebop.Service
	PolicyConfig     config.Config
	InventoryPath    string
	OperationTimeout time.Duration
}

func (executor BebopExecutor) Execute(ctx context.Context, job config.MaintenanceJob, invocation Invocation) (Outcome, error) {
	if executor.Service == nil {
		return Outcome{}, fmt.Errorf("maintenance executor has no Bebop service")
	}
	resolution, err := resolve.Resolve(job.Target, "", executor.InventoryPath)
	if err != nil {
		return Outcome{}, err
	}
	cfg, err := executor.configFor(resolution)
	if err != nil {
		return Outcome{}, err
	}
	switch job.Type {
	case "backup":
		return executor.backup(ctx, job, invocation, resolution, cfg)
	case "doctor":
		return executor.doctor(ctx, resolution, cfg)
	case "update-check":
		return executor.updateCheck(ctx, job, resolution, cfg)
	default:
		return Outcome{}, fmt.Errorf("unsupported maintenance operation %q", job.Type)
	}
}

func (executor BebopExecutor) configFor(resolution resolve.Resolution) (config.Config, error) {
	if resolution.ConfigPath == "" {
		return executor.PolicyConfig, nil
	}
	return config.LoadFile(resolution.ConfigPath)
}

func (executor BebopExecutor) backup(ctx context.Context, job config.MaintenanceJob, invocation Invocation, resolution resolve.Resolution, cfg config.Config) (Outcome, error) {
	repository, err := backup.Open(cfg)
	if err != nil {
		return Outcome{}, err
	}
	host, tr, err := executor.Service.Inspect(ctx, resolution.Target, cfg)
	if err != nil {
		return Outcome{}, err
	}
	scope := MaintenanceScope(job, resolution.Target.String())
	result, err := backup.Create(ctx, repository, backup.CreateRequest{
		HostAlias: resolution.Alias,
		Target:    resolution.Target.String(),
		Host:      host,
		Config:    cfg,
		Service:   job.Service,
		Transport: tr,
		Maintenance: &backup.MaintenanceProvenance{
			Job:            job.Name,
			Scope:          scope,
			RunID:          invocation.RunID,
			JobFingerprint: invocation.JobFingerprint,
		},
	})
	if err != nil {
		return Outcome{}, err
	}
	details := Details{SnapshotID: result.Snapshot.SnapshotID, Resources: backupResourceCount(result.Snapshot), StoredSize: backupStoredSize(result.Snapshot)}
	if job.Retention.KeepLast == 0 {
		return Outcome{Result: Success, Details: details}, nil
	}
	retention, err := repository.PlanRetention(scope, job.Retention.KeepLast)
	if err != nil {
		details.RetentionFailure = true
		return Outcome{Result: Warning, Details: details}, fmt.Errorf("backup succeeded but plan retention: %w", err)
	}
	for _, snapshot := range retention.Remove {
		details.RetentionDeleted = append(details.RetentionDeleted, snapshot.SnapshotID)
	}
	details.RetentionCorruptSkipped = append(details.RetentionCorruptSkipped, retention.CorruptSkipped...)
	if err := repository.ApplyRetention(retention); err != nil {
		details.RetentionFailure = true
		return Outcome{Result: Warning, Details: details}, fmt.Errorf("backup succeeded but apply retention: %w", err)
	}
	if len(details.RetentionCorruptSkipped) > 0 {
		details.RetentionFailure = true
		return Outcome{Result: Warning, Details: details}, fmt.Errorf("backup succeeded but retention preserved corrupt snapshot(s): %s", strings.Join(details.RetentionCorruptSkipped, ", "))
	}
	return Outcome{Result: Success, Details: details}, nil
}

func (executor BebopExecutor) doctor(ctx context.Context, resolution resolve.Resolution, cfg config.Config) (Outcome, error) {
	result := preflight.Run(ctx, executor.Service, resolution.Target, cfg)
	details := Details{}
	for _, check := range result.Checks {
		details.Findings = append(details.Findings, Finding{Code: check.Code, Status: string(check.Status)})
		switch check.Status {
		case preflight.Pass:
			details.DoctorPass++
		case preflight.Warn:
			details.DoctorWarn++
		case preflight.Fail:
			details.DoctorFail++
		}
	}
	if err := result.FailureError(); err != nil {
		return Outcome{Result: Failure, Details: details}, err
	}
	if details.DoctorWarn > 0 {
		return Outcome{Result: Warning, Details: details}, nil
	}
	return Outcome{Result: Success, Details: details}, nil
}

func (executor BebopExecutor) updateCheck(ctx context.Context, job config.MaintenanceJob, resolution resolve.Resolution, cfg config.Config) (Outcome, error) {
	host, tr, err := executor.Service.Inspect(ctx, resolution.Target, cfg)
	if err != nil {
		return Outcome{}, err
	}
	if host.PackageManager != "apt" && host.PackageManager != "dnf5" {
		return Outcome{Result: Failure}, errs.New(errs.UnsupportedOS, "update awareness requires the target's reviewed package-management tools", nil)
	}
	details := Details{}
	if job.RefreshMetadata {
		locker, ok := tr.(transport.ApplyLocker)
		if !ok {
			return Outcome{Result: Failure}, errs.New(errs.ApplyLocked, "refreshing package metadata requires the Bebop target apply lock", nil)
		}
		lock, lockErr := locker.AcquireApplyLock(ctx)
		if lockErr != nil {
			return Outcome{Result: Failure}, errs.New(errs.ApplyLocked, "acquire target apply lock for update metadata refresh", lockErr)
		}
		refreshScript, packageManager := aptRefreshScript, "apt"
		if host.PackageManager == "dnf5" {
			refreshScript, packageManager = dnfRefreshScript, "DNF5"
		}
		_, refreshErr := tr.Run(ctx, transport.Request{Script: refreshScript, Privileged: true})
		releaseErr := lock.Release()
		if refreshErr != nil {
			return Outcome{Result: Failure, Details: details}, fmt.Errorf("refresh %s package metadata: %w", packageManager, refreshErr)
		}
		if releaseErr != nil {
			return Outcome{Result: Failure, Details: details}, fmt.Errorf("release target apply lock after package metadata refresh: %w", releaseErr)
		}
		details.MetadataRefreshed = true
	}
	if host.PackageManager == "dnf5" {
		_, checkErr := tr.Run(ctx, transport.Request{Script: dnfUpdateCheckScript})
		available, operationalErr := dnfUpdatesAvailable(checkErr)
		if operationalErr != nil {
			return Outcome{Result: Failure, Details: details}, fmt.Errorf("inspect available DNF5 package updates: %w", operationalErr)
		}
		if available {
			// DNF5 defines 100 as the non-error "updates available" result.
			count, countErr := tr.Run(ctx, transport.Request{Script: dnfUpdateCountScript})
			if countErr != nil {
				return Outcome{Result: Failure, Details: details}, fmt.Errorf("count available DNF5 package updates: %w", countErr)
			}
			details.UpdatesAvailable, _ = strconv.Atoi(strings.TrimSpace(count.Stdout))
			if details.UpdatesAvailable < 1 {
				return Outcome{Result: Failure, Details: details}, fmt.Errorf("count available DNF5 package updates: check-upgrade reported updates but deterministic query returned %q", strings.TrimSpace(count.Stdout))
			}
		}
		details.SecurityClassification = "unknown"
		return Outcome{Result: Success, Details: details}, nil
	}
	result, err := tr.Run(ctx, transport.Request{Script: aptUpdateSimulationScript})
	if err != nil {
		return Outcome{Result: Failure, Details: details}, fmt.Errorf("inspect available apt package updates: %w", err)
	}
	updates := ParseAPTUpdateSimulation(result.Stdout)
	details.UpdatesAvailable = updates.Total
	details.SecurityUpdates = updates.Security
	details.SecurityClassification = updates.SecurityClassification
	return Outcome{Result: Success, Details: details}, nil
}

const aptRefreshScript = "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root DEBIAN_FRONTEND=noninteractive apt-get update"
const aptUpdateSimulationScript = "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C apt-get -s -o Debug::NoLocking=true upgrade"
const dnfRefreshScript = "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C dnf5 -y makecache"
const dnfUpdateCheckScript = "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C dnf5 -y check-upgrade"
const dnfUpdateCountScript = "env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C dnf5 repoquery --upgrades --queryformat '%{name}\\n' | LC_ALL=C sort -u | sed '/^$/d' | wc -l"

func dnfUpdatesAvailable(err error) (bool, error) {
	if err == nil {
		return false, nil
	}
	var exit *transport.ExitError
	if errors.As(err, &exit) && exit.Code == 100 {
		return true, nil
	}
	return false, err
}

type APTUpdateSummary struct {
	Total                  int
	Security               int
	SecurityClassification string
}

// ParseAPTUpdateSimulation reads apt-get's stable simulation "Inst" records.
// Security origin strings are not consistently exposed by all supported apt
// versions, so any unclassifiable available update yields security=unknown.
func ParseAPTUpdateSimulation(output string) APTUpdateSummary {
	result := APTUpdateSummary{SecurityClassification: "known"}
	for _, line := range strings.Split(output, "\n") {
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		result.Total++
		if strings.Contains(strings.ToLower(line), "security") {
			result.Security++
		} else {
			result.SecurityClassification = "unknown"
		}
	}
	if result.Total == 0 {
		result.SecurityClassification = "known"
	}
	return result
}

// MaintenanceScope binds retention to an automated job's logical target and
// selected service. It intentionally excludes schedule/retention values so a
// policy adjustment can continue retaining that same job lineage.
func MaintenanceScope(job config.MaintenanceJob, resolvedTarget string) string {
	semantic := struct {
		Job     string `json:"job"`
		Target  string `json:"target"`
		Service string `json:"service"`
	}{Job: job.Name, Target: resolvedTarget, Service: job.Service}
	encoded, _ := json.Marshal(semantic)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func backupResourceCount(manifest backup.Manifest) int {
	count := 0
	for _, service := range manifest.Services {
		count += len(service.Resources)
	}
	return count
}

func backupStoredSize(manifest backup.Manifest) int64 {
	var total int64
	for _, service := range manifest.Services {
		for _, resource := range service.Resources {
			total += resource.StoredSize
		}
	}
	return total
}
