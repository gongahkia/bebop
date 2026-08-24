package cli

import (
	"context"
	"flag"
	"fmt"
	"text/tabwriter"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/resolve"
	storagepolicy "github.com/bebop-home/bebop/internal/storage"
)

func (r *Runner) storage(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("storage requires list, show, inspect, doctor, or adopt")
	}
	switch arguments[0] {
	case "list":
		return r.storageList(arguments[1:])
	case "show":
		return r.storageShow(arguments[1:])
	case "inspect":
		return r.storageInspect(arguments[1:])
	case "doctor":
		return r.storageDoctor(arguments[1:])
	case "adopt":
		return r.storageAdopt(arguments[1:])
	default:
		return fmt.Errorf("unknown storage command %q", arguments[0])
	}
}

func (r *Runner) storageTarget(arguments []string, usage string) (config.Config, facts.HostFacts, bool, error) {
	fs := flag.NewFlagSet(usage, flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return config.Config{}, facts.HostFacts{}, false, err
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return config.Config{}, facts.HostFacts{}, false, err
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := config.LoadFile(path)
	if err != nil {
		return config.Config{}, facts.HostFacts{}, false, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	host, _, err := r.Service.Inspect(ctx, resolution.Target, cfg)
	return cfg, host, common.json, err
}

func (r *Runner) storageList(arguments []string) error {
	cfg, host, jsonOutput, err := r.storageTarget(arguments, "storage list")
	if err != nil {
		return err
	}
	assessments := storagepolicy.AssessAll(cfg.Storage, host.Storage)
	if jsonOutput {
		return writeJSON(r.Out, assessments)
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tMOUNT\tUUID\tSTATE\tDETAIL")
	for _, assessment := range assessments {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", assessment.Resource.Name, assessment.Resource.Mount, assessment.Resource.FilesystemUUID, assessment.State, assessment.Detail)
	}
	_ = writer.Flush()
	if len(assessments) == 0 {
		fmt.Fprintln(r.Out, "No storage resources are declared.")
	}
	return nil
}

func (r *Runner) storageShow(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("storage show requires a storage resource name")
	}
	name := arguments[0]
	cfg, host, jsonOutput, err := r.storageTarget(arguments[1:], "storage show")
	if err != nil {
		return err
	}
	resource, found := storagepolicy.Find(cfg.Storage, name)
	if !found {
		return fmt.Errorf("unknown declared storage resource %q", name)
	}
	assessment := storagepolicy.Assess(resource, host.Storage)
	if jsonOutput {
		return writeJSON(r.Out, assessment)
	}
	fmt.Fprintf(r.Out, "Storage     %s\nMount       %s\nUUID        %s\nState       %s\nDetail      %s\n", resource.Name, resource.Mount, resource.FilesystemUUID, assessment.State, assessment.Detail)
	return nil
}

func (r *Runner) storageInspect(arguments []string) error {
	_, host, _, err := r.storageTarget(arguments, "storage inspect")
	if err != nil {
		return err
	}
	return writeJSON(r.Out, host.Storage)
}

func (r *Runner) storageDoctor(arguments []string) error {
	cfg, host, jsonOutput, err := r.storageTarget(arguments, "storage doctor")
	if err != nil {
		return err
	}
	assessments := storagepolicy.AssessAll(cfg.Storage, host.Storage)
	if jsonOutput {
		return writeJSON(r.Out, assessments)
	}
	failed := 0
	for _, assessment := range assessments {
		status := "PASS"
		if assessment.State != storagepolicy.Ready {
			status = "FAIL"
			failed++
		}
		fmt.Fprintf(r.Out, "%s  %s  %s\n", status, assessment.Resource.Name, assessment.Detail)
	}
	if len(assessments) == 0 {
		fmt.Fprintln(r.Out, "WARN  storage  no declared storage resources")
	}
	if failed > 0 {
		return fmt.Errorf("%d declared storage resources are not ready", failed)
	}
	return nil
}

func (r *Runner) storageAdopt(arguments []string) error {
	fs := flag.NewFlagSet("storage adopt", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	mount := fs.String("mount", "", "existing target mount point")
	uuid := fs.String("filesystem-uuid", "", "filesystem UUID observed on the target")
	filesystemType := fs.String("filesystem-type", "", "optional filesystem type")
	managed := fs.Bool("managed-mount", false, "authorize Bebop to persist/mount this existing filesystem")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 || (fs.NArg() == 1 && common.target == "") {
		return fmt.Errorf("storage adopt requires NAME and HOST (or --target)")
	}
	name := fs.Arg(0)
	// resolveTarget accepts exactly one positional host; remove the preceding
	// resource name after flag parsing without re-parsing user-controlled flags.
	reference := ""
	if fs.NArg() == 2 {
		reference = fs.Arg(1)
	}
	resource := config.StorageResource{Name: name, Mount: *mount, FilesystemUUID: *uuid, FilesystemType: *filesystemType, ManagedMount: *managed}
	probe := config.Defaults()
	probe.Storage.Resources = []config.StorageResource{resource}
	if err := config.Validate(probe); err != nil {
		return err
	}
	resolution, err := resolve.Resolve(reference, common.target, common.inventory)
	if err != nil {
		return err
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	host, _, err := r.Service.Inspect(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	assessment := storagepolicy.Assess(resource, host.Storage)
	if assessment.State != storagepolicy.Ready {
		return fmt.Errorf("storage adoption refused: observed target state is %s: %s", assessment.State, assessment.Detail)
	}
	if err := config.AdoptStorageResource(path, resource); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "Adopted storage %s: UUID %s mounted at %s\n", resource.Name, resource.FilesystemUUID, resource.Mount)
	return nil
}
