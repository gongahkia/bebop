// Package cli renders Bebop's human and JSON command-line interface.
package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bebop-home/bebop/internal/apply"
	"github.com/bebop-home/bebop/internal/bebop"
	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/errs"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/plan"
	"github.com/bebop-home/bebop/internal/resolve"
)

const Version = "0.1.0"

type Runner struct {
	Service *bebop.Service
	In      io.Reader
	Out     io.Writer
	Err     io.Writer
}

func New() *Runner {
	return &Runner{Service: bebop.NewService(), In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
}

func (r *Runner) Run(arguments []string) int {
	if len(arguments) == 0 {
		r.usage()
		return 2
	}
	var err error
	switch arguments[0] {
	case "version":
		fmt.Fprintf(r.Out, "bebop %s\n", Version)
	case "inspect":
		err = r.inspect(arguments[1:])
	case "host":
		err = r.host(arguments[1:])
	case "init":
		err = r.init(arguments[1:])
	case "plan":
		err = r.plan(arguments[1:])
	case "apply":
		err = r.apply(arguments[1:])
	case "doctor":
		err = r.doctor(arguments[1:])
	case "status":
		err = r.status(arguments[1:])
	case "help", "--help", "-h":
		r.usage()
	default:
		err = fmt.Errorf("unknown command %q", arguments[0])
	}
	if err == nil {
		return 0
	}
	fmt.Fprintln(r.Err, "error:", err)
	var categorized *errs.Error
	if errors.As(err, &categorized) && categorized.Code == errs.PlanBlocked {
		return 2
	}
	return 1
}

type commonFlags struct {
	target    string
	inventory string
	timeout   time.Duration
	json      bool
}

func addCommon(fs *flag.FlagSet, includeJSON bool) *commonFlags {
	flags := &commonFlags{}
	fs.StringVar(&flags.target, "target", "", "literal target: local or ssh://user@host[:port]")
	fs.StringVar(&flags.inventory, "inventory", inventory.DefaultPath, "path to host inventory")
	fs.DurationVar(&flags.timeout, "timeout", 30*time.Second, "per-command target operation timeout")
	if includeJSON {
		fs.BoolVar(&flags.json, "json", false, "write machine-readable JSON")
	}
	return flags
}

func resolveTarget(fs *flag.FlagSet, common *commonFlags) (resolve.Resolution, error) {
	if fs.NArg() > 1 {
		return resolve.Resolution{}, fmt.Errorf("accepts at most one host reference")
	}
	reference := ""
	if fs.NArg() == 1 {
		reference = fs.Arg(0)
	}
	return resolve.Resolve(reference, common.target, common.inventory)
}

func configured(fs *flag.FlagSet, resolution resolve.Resolution, requested string) string {
	set := false
	fs.Visit(func(flag *flag.Flag) {
		if flag.Name == "config" {
			set = true
		}
	})
	if !set && resolution.ConfigPath != "" {
		return resolution.ConfigPath
	}
	return requested
}

// normalizeArguments lets Bebop keep the conventional "command host --flag"
// form while using Go's deliberately simple flag package. Only known flags
// consume a following value; unknown flags remain for FlagSet to reject.
func normalizeArguments(fs *flag.FlagSet, arguments []string) []string {
	flags := make([]string, 0, len(arguments))
	positionals := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			positionals = append(positionals, arguments[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") || argument == "-" {
			positionals = append(positionals, argument)
			continue
		}
		flags = append(flags, argument)
		name := strings.TrimLeft(argument, "-")
		if equals := strings.IndexByte(name, '='); equals >= 0 {
			continue
		}
		registered := fs.Lookup(name)
		if registered == nil {
			continue
		}
		if _, boolean := registered.Value.(interface{ IsBoolFlag() bool }); boolean {
			continue
		}
		if index+1 < len(arguments) {
			index++
			flags = append(flags, arguments[index])
		}
	}
	return append(flags, positionals...)
}

func (r *Runner) inspect(arguments []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	host, _, err := r.Service.Inspect(ctx, resolution.Target, config.DefaultDataRoot)
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(r.Out, host)
	}
	renderFacts(r.Out, host)
	return nil
}

func (r *Runner) init(arguments []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, false)
	output := fs.String("output", "bebop.toml", "configuration file to create")
	force := fs.Bool("force", false, "replace an existing local configuration file")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	host, _, err := r.Service.Inspect(ctx, resolution.Target, config.DefaultDataRoot)
	if err != nil {
		return err
	}
	if !host.OS.Supported || !host.Systemd {
		return errs.New(errs.UnsupportedOS, "target is not a supported Debian-family system with systemd", nil)
	}
	if !*force {
		if _, err := os.Stat(*output); err == nil {
			return fmt.Errorf("%s already exists; use --force to replace it", *output)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.WriteFile(*output, []byte(config.Starter()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", *output, err)
	}
	fmt.Fprintln(r.Out, "Detected host")
	renderFacts(r.Out, host)
	fmt.Fprintf(r.Out, "\nCreated %s\n", *output)
	return nil
}

func (r *Runner) host(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("host requires add, remove, list, or show")
	}
	switch arguments[0] {
	case "add":
		return r.hostAdd(arguments[1:])
	case "remove":
		return r.hostRemove(arguments[1:])
	case "list":
		return r.hostList(arguments[1:])
	case "show":
		return r.hostShow(arguments[1:])
	default:
		return fmt.Errorf("unknown host command %q", arguments[0])
	}
}

func addInventoryPath(fs *flag.FlagSet) *string {
	return fs.String("inventory", inventory.DefaultPath, "path to host inventory")
}

func (r *Runner) hostAdd(arguments []string) error {
	fs := flag.NewFlagSet("host add", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	inventoryPath := addInventoryPath(fs)
	targetValue := fs.String("target", "", "target: ssh://user@host[:port] or local")
	configPath := fs.String("config", "", "relative desired-state config path")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("host add requires exactly one alias")
	}
	if *targetValue == "" {
		return fmt.Errorf("host add requires --target")
	}
	loaded, err := inventory.LoadOrEmpty(*inventoryPath)
	if err != nil {
		return err
	}
	if err := loaded.Add(fs.Arg(0), inventory.Host{Target: *targetValue, Config: *configPath}); err != nil {
		return err
	}
	if err := inventory.WriteFile(*inventoryPath, loaded); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "Added host %s to %s\n", fs.Arg(0), *inventoryPath)
	return nil
}

func (r *Runner) hostRemove(arguments []string) error {
	fs := flag.NewFlagSet("host remove", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	inventoryPath := addInventoryPath(fs)
	yes := fs.Bool("yes", false, "remove inventory metadata without a prompt")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("host remove requires exactly one alias")
	}
	if !*yes {
		return fmt.Errorf("host remove changes only local inventory metadata; repeat with --yes to confirm")
	}
	loaded, err := inventory.LoadFile(*inventoryPath)
	if err != nil {
		return err
	}
	if err := loaded.Remove(fs.Arg(0)); err != nil {
		return err
	}
	if err := inventory.WriteFile(*inventoryPath, loaded); err != nil {
		return err
	}
	fmt.Fprintf(r.Out, "Removed host %s from %s; no target was contacted.\n", fs.Arg(0), *inventoryPath)
	return nil
}

func (r *Runner) hostList(arguments []string) error {
	fs := flag.NewFlagSet("host list", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	inventoryPath := addInventoryPath(fs)
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("host list accepts no positional arguments")
	}
	loaded, err := inventory.LoadOrEmpty(*inventoryPath)
	if err != nil {
		return err
	}
	type entry struct {
		Name   string `json:"name"`
		Target string `json:"target"`
		Config string `json:"config,omitempty"`
	}
	entries := make([]entry, 0, len(loaded.Hosts))
	for _, alias := range loaded.SortedAliases() {
		host := loaded.Hosts[alias]
		entries = append(entries, entry{Name: alias, Target: host.Target, Config: host.Config})
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Version int     `json:"version"`
			Hosts   []entry `json:"hosts"`
		}{Version: loaded.Version, Hosts: entries})
	}
	if len(entries) == 0 {
		fmt.Fprintln(r.Out, "No hosts registered.")
		return nil
	}
	fmt.Fprintln(r.Out, "NAME\tTARGET\tCONFIG")
	for _, host := range entries {
		fmt.Fprintf(r.Out, "%s\t%s\t%s\n", host.Name, host.Target, host.Config)
	}
	return nil
}

func (r *Runner) hostShow(arguments []string) error {
	fs := flag.NewFlagSet("host show", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	inventoryPath := addInventoryPath(fs)
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("host show requires exactly one alias")
	}
	loaded, err := inventory.LoadFile(*inventoryPath)
	if err != nil {
		return err
	}
	host, exists := loaded.Hosts[fs.Arg(0)]
	if !exists {
		return errs.New(errs.InventoryInvalid, "unknown host alias: "+fs.Arg(0), nil)
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Name   string `json:"name"`
			Target string `json:"target"`
			Config string `json:"config,omitempty"`
		}{Name: fs.Arg(0), Target: host.Target, Config: host.Config})
	}
	fmt.Fprintf(r.Out, "Name    %s\nTarget  %s\nConfig  %s\n", fs.Arg(0), host.Target, host.Config)
	return nil
}

func (r *Runner) plan(arguments []string) error {
	fs := flag.NewFlagSet("plan", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	showCommands := fs.Bool("show-commands", false, "include exact planned shell scripts in human output")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
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
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	_, _, result, err := r.Service.Plan(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	if common.json {
		if err := writeJSON(r.Out, result); err != nil {
			return err
		}
	} else {
		renderPlan(r.Out, result, *showCommands)
	}
	if blocked(result) {
		return errs.New(errs.PlanBlocked, "plan contains blocked changes", nil)
	}
	return nil
}

func (r *Runner) apply(arguments []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "path to bebop.toml")
	yes := fs.Bool("yes", false, "apply without interactive confirmation")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return err
	}
	if common.json && !*yes {
		return fmt.Errorf("apply --json requires --yes because prompts would corrupt JSON output")
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := config.LoadFile(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), applyTimeout(common.timeout))
	defer cancel()
	_, tr, reviewed, err := r.Service.Plan(ctx, resolution.Target, cfg)
	if err != nil {
		return err
	}
	if !common.json {
		renderPlan(r.Out, reviewed, false)
	}
	if blocked(reviewed) {
		if common.json {
			_ = writeJSON(r.Out, struct {
				Plan plan.Plan `json:"plan"`
			}{reviewed})
		}
		return errs.New(errs.PlanBlocked, "plan contains blocked changes; no mutation attempted", nil)
	}
	if len(reviewed.Changes) == 0 {
		if common.json {
			return writeJSON(r.Out, struct {
				Plan   plan.Plan    `json:"plan"`
				Result apply.Result `json:"result"`
			}{reviewed, apply.Result{Final: reviewed}})
		} else {
			fmt.Fprintln(r.Out, "No changes. Target already matches the desired state.")
		}
		return nil
	}
	if !*yes {
		fmt.Fprint(r.Out, "\nApply these changes? [y/N] ")
		answer, readErr := bufio.NewReader(r.In).ReadString('\n')
		if readErr != nil && len(answer) == 0 {
			return fmt.Errorf("read confirmation: %w", readErr)
		}
		if strings.ToLower(strings.TrimSpace(answer)) != "y" && strings.ToLower(strings.TrimSpace(answer)) != "yes" {
			fmt.Fprintln(r.Out, "Aborted.")
			return nil
		}
	}
	result, err := apply.Execute(ctx, reviewed, tr, r.Service.Planner.Modules(), func(replanContext context.Context) (plan.Plan, error) {
		_, _, next, buildErr := r.Service.Plan(replanContext, resolution.Target, cfg)
		return next, buildErr
	})
	if err != nil {
		return err
	}
	if common.json {
		return writeJSON(r.Out, struct {
			Plan   plan.Plan    `json:"plan"`
			Result apply.Result `json:"result"`
		}{reviewed, result})
	}
	fmt.Fprintln(r.Out, "\nApplied and verified:")
	for _, id := range result.Verified {
		fmt.Fprintf(r.Out, "  ✓ %s\n", id)
	}
	if len(result.Final.Warnings) > 0 {
		fmt.Fprintln(r.Out, "\nAction required:")
		renderWarnings(r.Out, result.Final.Warnings)
	}
	fmt.Fprintln(r.Out, "Convergence verified. A new plan has no executable changes.")
	return nil
}

func (r *Runner) doctor(arguments []string) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "configuration used to select the data root when present")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return err
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := loadOptionalConfig(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	host, _, err := r.Service.Inspect(ctx, resolution.Target, cfg.Storage.DataRoot)
	if err != nil {
		return err
	}
	report := doctorReport(host)
	if common.json {
		return writeJSON(r.Out, report)
	}
	for _, check := range report.Checks {
		symbol := "✓"
		if check.Status == "warning" {
			symbol = "!"
		}
		if check.Status == "failure" {
			symbol = "✗"
		}
		fmt.Fprintf(r.Out, "%s %s\n", symbol, check.Message)
	}
	return nil
}

func (r *Runner) status(arguments []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	common := addCommon(fs, true)
	configPath := fs.String("config", "bebop.toml", "configuration used to select the data root when present")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	resolution, err := resolveTarget(fs, common)
	if err != nil {
		return err
	}
	path := configured(fs, resolution, *configPath)
	cfg, err := loadOptionalConfig(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), common.timeout)
	defer cancel()
	host, _, err := r.Service.Inspect(ctx, resolution.Target, cfg.Storage.DataRoot)
	if err != nil {
		return err
	}
	report := statusReport(host)
	if common.json {
		return writeJSON(r.Out, report)
	}
	storage := "no unconfigured disks detected"
	if len(report.UnconfiguredStorage) > 0 {
		storage = "unconfigured disks detected; Bebop M0 will not modify them"
	}
	fmt.Fprintf(r.Out, "Host        %s\nOS          %s (%s)\nDocker      %s\nTailscale   %s\nUpdates     %s\nSSH         %s\nData root   %s\nStorage     %s\nOverall     %s\n", report.Host, report.OS, report.Architecture, report.Docker, report.Tailscale, report.Updates, report.SSH, report.DataRoot, storage, report.Overall)
	return nil
}

func loadOptionalConfig(filename string) (config.Config, error) {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return config.Defaults(), nil
	}
	return config.LoadFile(filename)
}

func applyTimeout(requested time.Duration) time.Duration {
	if requested == 30*time.Second {
		return 15 * time.Minute
	}
	return requested
}

func blocked(result plan.Plan) bool {
	for _, change := range result.Changes {
		if change.Blocked != "" {
			return true
		}
	}
	return false
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func renderFacts(output io.Writer, host facts.HostFacts) {
	fmt.Fprintf(output, "\nHostname       %s\nOS             %s\nArchitecture   %s\nPackage mgr    %s\nInit           %s\nDocker         %s\nTailscale      %s\n", host.Hostname, host.OS.Display(), host.Architecture, host.PackageManager, host.InitSystem, dockerState(host), tailscaleState(host))
}

func renderPlan(output io.Writer, result plan.Plan, showCommands bool) {
	fmt.Fprintf(output, "Target: %s\nPlan fingerprint: %s\n", result.Target, result.Fingerprint)
	if len(result.Changes) == 0 {
		fmt.Fprintln(output, "\nNo changes.")
	}
	for _, change := range result.Changes {
		marker := "+"
		if change.Blocked != "" {
			marker = "!"
		}
		fmt.Fprintf(output, "\n%s %s\n  %s\n  Current: %s\n  Desired: %s\n  Risk: %s\n", marker, change.ID, change.Summary, change.Current, change.Desired, change.Risk)
		if change.Blocked != "" {
			fmt.Fprintf(output, "  Blocked: %s\n", change.Blocked)
		}
		if showCommands && change.Action.Script != "" {
			fmt.Fprintln(output, "  Planned script:")
			for _, line := range strings.Split(change.Action.Script, "\n") {
				fmt.Fprintf(output, "    %s\n", line)
			}
		}
	}
	if len(result.Warnings) > 0 {
		fmt.Fprintln(output, "\nWarnings:")
		renderWarnings(output, result.Warnings)
	}
	blockedCount := 0
	destructive := 0
	for _, change := range result.Changes {
		if change.Blocked != "" {
			blockedCount++
		}
		if change.Risk == plan.Destructive {
			destructive++
		}
	}
	fmt.Fprintf(output, "\n%d changes, %d blocked, %d destructive\n", len(result.Changes), blockedCount, destructive)
}

func renderWarnings(output io.Writer, warnings []plan.Warning) {
	for _, warning := range warnings {
		fmt.Fprintf(output, "  ! %s", warning.Summary)
		if warning.Resolution != "" {
			fmt.Fprintf(output, "\n    %s", warning.Resolution)
		}
		fmt.Fprintln(output)
	}
}

func (r *Runner) usage() {
	fmt.Fprint(r.Out, `Bebop — deterministic home-server converger

Usage:
  bebop version
  bebop inspect --target local|ssh://user@host[:port] [--json]
  bebop init --target TARGET [--output bebop.toml] [--force]
  bebop plan --target TARGET --config bebop.toml [--json] [--show-commands]
  bebop apply --target TARGET --config bebop.toml [--yes]
  bebop doctor --target TARGET [--json]
  bebop status --target TARGET [--json]
`)
}
