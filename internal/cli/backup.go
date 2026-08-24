package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/bebop-home/bebop/internal/apply"
	"github.com/bebop-home/bebop/internal/backup"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/resolve"
	"github.com/bebop-home/bebop/internal/target"
	"github.com/bebop-home/bebop/internal/transport"
)

func (r *Runner) backup(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("backup requires create, list, show, verify, or restore")
	}
	switch arguments[0] {
	case "create":
		return r.backupCreate(arguments[1:])
	case "list":
		return r.backupList(arguments[1:])
	case "show":
		return r.backupShow(arguments[1:])
	case "verify":
		return r.backupVerify(arguments[1:])
	case "restore":
		return r.backupRestore(arguments[1:])
	default:
		return fmt.Errorf("unknown backup command %q", arguments[0])
	}
}

func (r *Runner) backupCreate(arguments []string) error {
	fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	serviceName := fs.String("service", "", "back up one declared service")
	yes := fs.Bool("yes", false, "create backup without interactive confirmation")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if common.json && !*yes {
		return fmt.Errorf("backup create --json requires --yes because prompts would corrupt JSON output")
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return err
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	repository, err := backup.Open(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout(common.timeout))
	defer cancel()
	host, tr, err := r.Service.Inspect(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	deployments, err := backupDeclarations(cfg, *serviceName)
	if err != nil {
		return err
	}
	if !common.json {
		fmt.Fprintf(r.Out, "Backup target: %s\nRepository: %s\n", resolution.Target, repository.Root())
		for _, deployment := range deployments {
			fmt.Fprintf(r.Out, "\nService %s (%s consistency)\n", deployment.Name, deployment.BackupConsistency)
			for _, resource := range deployment.Data {
				fmt.Fprintf(r.Out, "  %s %s\n", resource.Type, resourceDestination(resource))
			}
		}
	}
	if !*yes && !confirmBackup(r, "\nCreate this backup? [y/N] ") {
		return nil
	}
	result, err := backup.Create(ctx, repository, backup.CreateRequest{HostAlias: resolution.Alias, Target: resolution.Target.String(), Host: host, Config: cfg, Service: *serviceName, Transport: tr})
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(r.Out, result)
	}
	stored := int64(0)
	for _, service := range result.Snapshot.Services {
		for _, resource := range service.Resources {
			stored += resource.StoredSize
		}
	}
	fmt.Fprintf(r.Out, "\nSnapshot: %s\nResources: %d\nStored: %d bytes\nResult: complete\n", result.Snapshot.SnapshotID, resourceCount(result.Snapshot), stored)
	return nil
}

func backupDeclarations(cfg config.Config, only string) ([]backupServiceDeclaration, error) {
	// This deliberately calls the canonical service resolver through the backup
	// request later; this local presentation path only avoids hiding data scope.
	result := make([]backupServiceDeclaration, 0)
	for _, service := range cfg.Services {
		if only != "" && service.Name != only {
			continue
		}
		if len(service.Data) == 0 {
			continue
		}
		result = append(result, backupServiceDeclaration{Name: service.Name, BackupConsistency: service.Backup.Consistency, Data: service.Data})
	}
	if only != "" && len(result) == 0 {
		return nil, errs.New(errs.ConfigInvalid, "service "+only+" has no declared persistent data", nil)
	}
	if len(result) == 0 {
		return nil, errs.New(errs.ConfigInvalid, "no services declare persistent data for backup", nil)
	}
	return result, nil
}

type backupServiceDeclaration struct {
	Name, BackupConsistency string
	Data                    []config.DataResource
}

func resourceDestination(resource config.DataResource) string {
	if resource.Type == "volume" {
		return resource.Volume
	}
	return resource.Path
}

func (r *Runner) backupList(arguments []string) error {
	fs := flag.NewFlagSet("backup list", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("backup list accepts no positional arguments")
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	repository, err := backup.Open(cfg)
	if err != nil {
		return err
	}
	snapshots, err := repository.List()
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Snapshots []backup.SnapshotSummary `json:"snapshots"`
		}{snapshots})
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "SNAPSHOT\tHOST\tSERVICE\tCREATED\tSIZE")
	for _, snapshot := range snapshots {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%d bytes\n", snapshot.SnapshotID, snapshot.HostAlias, strings.Join(snapshot.Services, ","), snapshot.CreatedAt.Local().Format("2006-01-02 15:04"), snapshot.StoredSize)
	}
	return writer.Flush()
}

func (r *Runner) backupShow(arguments []string) error {
	fs := flag.NewFlagSet("backup show", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("backup show requires exactly one snapshot identifier")
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	repository, err := backup.Open(cfg)
	if err != nil {
		return err
	}
	manifest, err := repository.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, manifest)
	}
	fmt.Fprintf(r.Out, "Snapshot       %s\nSource         %s\nCreated        %s\nSchema         %d\nDigest         %s\n", manifest.SnapshotID, manifest.Source.Target, manifest.CreatedAt.Local().Format("2006-01-02 15:04:05 MST"), manifest.SchemaVersion, manifest.Digest)
	for _, service := range manifest.Services {
		fmt.Fprintf(r.Out, "\nService %s (%s consistency)\n", service.Name, service.Consistency)
		for _, resource := range service.Resources {
			fmt.Fprintf(r.Out, "  %s  %s  %d bytes  sha256:%s\n", resource.Name, resource.Type, resource.StoredSize, resource.SHA256)
		}
	}
	return nil
}

func (r *Runner) backupVerify(arguments []string) error {
	fs := flag.NewFlagSet("backup verify", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("backup verify requires exactly one snapshot identifier")
	}
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	repository, err := backup.Open(cfg)
	if err != nil {
		return err
	}
	manifest, err := repository.Verify(fs.Arg(0))
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Snapshot backup.Manifest `json:"snapshot"`
			Verified bool            `json:"verified"`
		}{manifest, true})
	}
	fmt.Fprintf(r.Out, "Snapshot %s verified: %d resources, sha256 digests match.\n", manifest.SnapshotID, resourceCount(manifest))
	return nil
}

func (r *Runner) backupRestore(arguments []string) error {
	fs := flag.NewFlagSet("backup restore", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	serviceName := fs.String("service", "", "restore one service from the snapshot")
	out := fs.String("out", "", "write a portable restore plan and do not mutate the target")
	planPath := fs.String("plan", "", "apply a previously written restore plan")
	yes := fs.Bool("yes", false, "restore without interactive confirmation")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if common.json && !*yes {
		return fmt.Errorf("backup restore --json requires --yes because prompts would corrupt JSON output")
	}
	if *planPath != "" {
		if fs.NArg() != 0 || common.target != "" || *out != "" {
			return fmt.Errorf("backup restore --plan cannot be combined with a snapshot, target, or --out")
		}
		return r.applyRestorePlan(*planPath, *configPath, flagWasSet(fs, "config"), common, *yes)
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return fmt.Errorf("backup restore requires SNAPSHOT and an optional destination host reference")
	}
	if *out != "" && *yes {
		return fmt.Errorf("backup restore --out writes a review artifact and cannot be combined with --yes")
	}
	snapshotID := fs.Arg(0)
	resolution, err := resolveRestoreTarget(fs, common)
	if err != nil {
		return err
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	repository, err := backup.Open(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout(common.timeout))
	defer cancel()
	host, tr, err := r.Service.Inspect(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	absoluteConfig, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	reviewed, err := backup.BuildRestorePlan(ctx, repository, backup.RestoreRequest{SnapshotID: snapshotID, HostAlias: resolution.Alias, Target: resolution.Target.String(), ConfigPath: absoluteConfig, Config: cfg, Host: host, Service: *serviceName, Transport: tr})
	if err != nil {
		return err
	}
	if *out != "" {
		if err := backup.WriteRestorePlan(*out, reviewed); err != nil {
			return err
		}
		if common.json {
			return writeJSON(r.Out, reviewed)
		}
		renderRestorePlan(r.Out, reviewed)
		fmt.Fprintf(r.Out, "\nWrote portable restore plan: %s\n", *out)
		return nil
	}
	return r.reviewAndApplyRestore(ctx, repository, reviewed, cfg, resolution, host, tr, *yes, common.json)
}

func resolveRestoreTarget(fs *flag.FlagSet, common *commonFlags) (resolve.Resolution, error) {
	if fs.NArg() == 2 {
		if common.target != "" {
			return resolve.Resolution{}, fmt.Errorf("backup restore destination is ambiguous: use a host reference or --target, not both")
		}
		return resolve.Resolve(fs.Arg(1), "", common.inventory)
	}
	if common.target == "" {
		return resolve.Resolution{}, fmt.Errorf("backup restore requires a destination host reference or --target")
	}
	return resolve.Resolve("", common.target, common.inventory)
}

func (r *Runner) applyRestorePlan(filename, requestedConfig string, configExplicit bool, common *commonFlags, yes bool) error {
	saved, err := backup.LoadRestorePlan(filename)
	if err != nil {
		return err
	}
	if err := validateRestoreInventory(saved, common.inventory); err != nil {
		return err
	}
	configSource := saved.ConfigPath
	if configExplicit {
		configSource = requestedConfig
	}
	if configSource == "" {
		return errs.New(errs.ConfigInvalid, "restore plan does not record a configuration path; provide --config", nil)
	}
	cfg, err := config.LoadFile(configSource)
	if err != nil {
		return err
	}
	repository, err := backup.Open(cfg)
	if err != nil {
		return err
	}
	targetValue, err := target.Parse(saved.Target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout(common.timeout))
	defer cancel()
	host, tr, err := r.Service.Inspect(ctx, targetValue, cfg)
	if err != nil {
		return err
	}
	fresh, err := backup.BuildRestorePlan(ctx, repository, backup.RestoreRequest{SnapshotID: saved.SnapshotID, HostAlias: saved.HostAlias, Target: targetValue.String(), ConfigPath: configSource, Config: cfg, Host: host, Service: restorePlanService(saved), Transport: tr})
	if err != nil {
		return err
	}
	if fresh.Fingerprint != saved.Fingerprint {
		return errs.New(errs.PlanStale, "restore plan is stale; destination, configuration, snapshot, or target identity changed", nil)
	}
	resolution := resolve.Resolution{Alias: saved.HostAlias, Target: targetValue}
	return r.reviewAndApplyRestore(ctx, repository, saved, cfg, resolution, host, tr, yes, common.json)
}

func restorePlanService(plan backup.RestorePlan) string {
	if len(plan.Services) == 1 {
		return plan.Services[0].Name
	}
	return ""
}

func validateRestoreInventory(saved backup.RestorePlan, inventoryPath string) error {
	if saved.HostAlias == "" {
		return nil
	}
	loaded, err := inventory.LoadFile(inventoryPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	host, exists := loaded.Hosts[saved.HostAlias]
	if exists && host.Target != saved.Target {
		return errs.New(errs.TargetIdentityMismatch, "inventory alias "+saved.HostAlias+" no longer resolves to the target reviewed by this restore plan", nil)
	}
	return nil
}

func (r *Runner) reviewAndApplyRestore(ctx context.Context, repository backup.Repository, reviewed backup.RestorePlan, cfg config.Config, resolution resolve.Resolution, host facts.HostFacts, tr transport.Transport, yes, jsonOutput bool) error {
	if !jsonOutput {
		renderRestorePlan(r.Out, reviewed)
	}
	if !yes && !confirmBackup(r, "\nRestore this snapshot into the empty destinations shown above? [y/N] ") {
		return nil
	}
	// Reinspect and rebuild directly before mutation, matching normal saved-plan
	// semantics and catching destination data or wrong-host drift during review.
	freshHost, freshTransport, err := r.Service.Inspect(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	fresh, err := backup.BuildRestorePlan(ctx, repository, backup.RestoreRequest{SnapshotID: reviewed.SnapshotID, HostAlias: resolution.Alias, Target: resolution.Target.String(), ConfigPath: reviewed.ConfigPath, Config: cfg, Host: freshHost, Service: restorePlanService(reviewed), Transport: freshTransport})
	if err != nil {
		return err
	}
	if fresh.Fingerprint != reviewed.Fingerprint {
		return errs.New(errs.PlanStale, "restore plan is stale; re-review the current destination state", nil)
	}
	result, err := backup.ApplyRestore(ctx, repository, reviewed, backup.RestoreRequest{SnapshotID: reviewed.SnapshotID, HostAlias: resolution.Alias, Target: resolution.Target.String(), ConfigPath: reviewed.ConfigPath, Config: cfg, Host: freshHost, Service: restorePlanService(reviewed), Transport: freshTransport})
	if err != nil {
		return err
	}
	// Restore owns data; normal Bebop apply then owns deployment convergence.
	_, convergeTransport, convergePlan, err := r.Service.Plan(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	if len(convergePlan.Changes) > 0 {
		_, err = apply.Execute(ctx, convergePlan, convergeTransport, cfg, r.Service.Planner.Modules(), func(replanContext context.Context) (plan.Plan, error) {
			_, _, next, buildErr := r.Service.Plan(replanContext, resolution.Target, cfg)
			return next, buildErr
		})
		if err != nil {
			return err
		}
	}
	if jsonOutput {
		return writeJSON(r.Out, result)
	}
	fmt.Fprintf(r.Out, "\nRestored snapshot %s to %s.\n", reviewed.SnapshotID, resolution.Target)
	for _, resource := range result.Restored {
		fmt.Fprintf(r.Out, "  ✓ %s\n", resource)
	}
	if len(result.NeedsConvergence) > 0 {
		fmt.Fprintln(r.Out, "Deployment was created/reconciled through the normal Bebop service plan.")
	}
	return nil
}

func renderRestorePlan(output io.Writer, plan backup.RestorePlan) {
	fmt.Fprintf(output, "Restore plan %s\nSnapshot: %s\nTarget: %s\nPolicy: %s\n", shortFingerprint(plan.Fingerprint), plan.SnapshotID, plan.Target, plan.Policy)
	for _, service := range plan.Services {
		fmt.Fprintf(output, "\nService %s (currently %s)\n", service.Name, service.Runtime)
		for _, resource := range service.Resources {
			state := "missing"
			if resource.Exists && resource.Empty {
				state = "empty"
			} else if resource.Exists {
				state = "NON-EMPTY (blocked)"
			}
			fmt.Fprintf(output, "  %s -> %s (%s)\n", resource.Name, resource.Destination, state)
		}
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(output, "\nWARN  %s\n", warning)
	}
}

func confirmBackup(r *Runner, prompt string) bool {
	fmt.Fprint(r.Out, prompt)
	answer, err := bufio.NewReader(r.In).ReadString('\n')
	if err != nil && len(answer) == 0 {
		return false
	}
	confirmed := strings.ToLower(strings.TrimSpace(answer))
	if confirmed == "y" || confirmed == "yes" {
		return true
	}
	fmt.Fprintln(r.Out, "Aborted.")
	return false
}

func resourceCount(manifest backup.Manifest) int {
	count := 0
	for _, service := range manifest.Services {
		count += len(service.Resources)
	}
	return count
}
