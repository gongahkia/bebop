package cli

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/recipes"
)

func (r *Runner) recipe(arguments []string) error {
	if len(arguments) == 0 {
		return fmt.Errorf("recipe requires list, show, init, upgrade, or validate")
	}
	switch arguments[0] {
	case "list":
		return r.recipeList(arguments[1:])
	case "show":
		return r.recipeShow(arguments[1:])
	case "init":
		return r.recipeInit(arguments[1:])
	case "upgrade":
		return r.recipeUpgrade(arguments[1:])
	case "validate":
		return r.recipeValidate(arguments[1:])
	default:
		return fmt.Errorf("unknown recipe command %q", arguments[0])
	}
}

type recipeSummary struct {
	ID                 string   `json:"id"`
	Version            string   `json:"version"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	ApplicationVersion string   `json:"application_version"`
	Architectures      []string `json:"architectures"`
}

func summary(recipe recipes.Recipe) recipeSummary {
	return recipeSummary{ID: recipe.ID, Version: recipe.Version, Name: recipe.Name, Description: recipe.Description, ApplicationVersion: recipe.ApplicationVersion, Architectures: recipe.Architectures}
}

func (r *Runner) recipeList(arguments []string) error {
	fs := flag.NewFlagSet("recipe list", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("recipe list accepts no positional arguments")
	}
	catalog, err := recipes.Builtin()
	if err != nil {
		return err
	}
	entries := make([]recipeSummary, 0)
	for _, recipe := range catalog.List() {
		entries = append(entries, summary(recipe))
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Recipes []recipeSummary `json:"recipes"`
		}{entries})
	}
	writer := tabwriter.NewWriter(r.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tVERSION\tDESCRIPTION")
	for _, entry := range entries {
		fmt.Fprintf(writer, "%s\t%s\t%s\n", entry.ID, entry.Version, entry.Description)
	}
	return writer.Flush()
}

func (r *Runner) recipeShow(arguments []string) error {
	fs := flag.NewFlagSet("recipe show", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	version := fs.String("version", "", "specific locally bundled recipe version")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("recipe show requires exactly one recipe ID")
	}
	catalog, err := recipes.Builtin()
	if err != nil {
		return err
	}
	recipe, err := catalog.Find(fs.Arg(0), *version)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, recipe)
	}
	fmt.Fprintf(r.Out, "%s (%s)\nRecipe version: %s\nApplication version: %s\nArchitectures: %s\nHealth: %s\nImages:\n", recipe.Name, recipe.ID, recipe.Version, recipe.ApplicationVersion, strings.Join(recipe.Architectures, ", "), recipe.Health)
	for _, image := range recipe.Images {
		fmt.Fprintf(r.Out, "  %s\n", image)
	}
	if len(recipe.Parameters) > 0 {
		fmt.Fprintln(r.Out, "Parameters:")
		for _, parameter := range recipe.Parameters {
			required := "required"
			if parameter.HasDefault {
				required = "default " + parameter.Default
			}
			fmt.Fprintf(r.Out, "  %s (%s, %s)\n", parameter.Name, parameter.Type, required)
		}
	}
	if len(recipe.Secrets) > 0 {
		fmt.Fprintln(r.Out, "Required secret environment keys:")
		for _, secret := range recipe.Secrets {
			fmt.Fprintf(r.Out, "  %s (%s)\n", secret.Name, secret.Environment)
		}
	}
	if len(recipe.Data) > 0 {
		fmt.Fprintln(r.Out, "Persistent data:")
		for _, resource := range recipe.Data {
			if resource.Type == "volume" {
				fmt.Fprintf(r.Out, "  %s: named volume %s\n", resource.Name, resource.Volume)
			} else {
				fmt.Fprintf(r.Out, "  %s: bind path %s\n", resource.Name, resource.Path)
			}
		}
	}
	fmt.Fprintf(r.Out, "\n%s\n%s\n", recipe.Description, recipe.Homepage)
	return nil
}

type stringValues []string

func (values *stringValues) String() string { return strings.Join(*values, ",") }
func (values *stringValues) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func (r *Runner) recipeInit(arguments []string) error {
	fs := flag.NewFlagSet("recipe init", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	serviceName := fs.String("service", "", "ordinary Bebop service name to create")
	configPath := fs.String("config", "bebop.toml", "configuration to extend")
	output := fs.String("output", "", "controller-relative source directory (default services/<service>)")
	version := fs.String("version", "", "specific locally bundled recipe version")
	secretFile := fs.String("secret-file", "", "controller-relative M3 secret environment file reference")
	dryRun := fs.Bool("dry-run", false, "render the ordinary output without writing local files")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	var parameters stringValues
	fs.Var(&parameters, "param", "typed recipe parameter as name=value; repeatable")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 || *serviceName == "" {
		return fmt.Errorf("recipe init requires a recipe ID and --service NAME")
	}
	current, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	catalog, err := recipes.Builtin()
	if err != nil {
		return err
	}
	recipe, err := catalog.Find(fs.Arg(0), *version)
	if err != nil {
		return err
	}
	source := *output
	if source == "" {
		source = "services/" + *serviceName
	}
	materialization, err := recipe.Materialize(recipes.Request{Service: *serviceName, Source: source, Parameters: parameters, SecretFile: *secretFile})
	if err != nil {
		return err
	}
	if *dryRun {
		return r.renderRecipeMaterialization(materialization, recipes.WriteResult{ConfigPath: *configPath}, true, *jsonOutput)
	}
	result, err := recipes.Initialize(*configPath, current, materialization)
	if err != nil {
		return err
	}
	return r.renderRecipeMaterialization(materialization, result, false, *jsonOutput)
}

func (r *Runner) recipeUpgrade(arguments []string) error {
	fs := flag.NewFlagSet("recipe upgrade", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	configPath := fs.String("config", "bebop.toml", "configuration containing the generated service")
	to := fs.String("to", "", "specific locally bundled recipe version")
	secretFile := fs.String("secret-file", "", "updated controller-relative secret file reference when required")
	dryRun := fs.Bool("dry-run", false, "render the local source update without writing files")
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	var parameters stringValues
	fs.Var(&parameters, "param", "typed replacement parameter as name=value; repeatable")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 1 || *to == "" {
		return fmt.Errorf("recipe upgrade requires a service name and --to VERSION")
	}
	current, err := config.LoadFile(*configPath)
	if err != nil {
		return err
	}
	service, found := serviceByName(current, fs.Arg(0))
	if !found {
		return fmt.Errorf("unknown configured service %q", fs.Arg(0))
	}
	source := filepath.Join(current.SourceDirectory(), filepath.FromSlash(service.Source))
	provenance, err := recipes.LoadProvenance(filepath.Join(source, recipes.ProvenanceFilename))
	if err != nil {
		return fmt.Errorf("service %q is not valid recipe-managed source: %w", service.Name, err)
	}
	catalog, err := recipes.Builtin()
	if err != nil {
		return err
	}
	previous, err := catalog.Find(provenance.RecipeID, provenance.RecipeVersion)
	if err != nil || previous.Fingerprint != provenance.RecipeFingerprint {
		return fmt.Errorf("recipe provenance references an unavailable or changed built-in recipe")
	}
	nextRecipe, err := catalog.Find(provenance.RecipeID, *to)
	if err != nil {
		return err
	}
	effectiveSecretFile := provenance.SecretFile
	if *secretFile != "" {
		effectiveSecretFile = *secretFile
	}
	if len(nextRecipe.Secrets) == 0 {
		effectiveSecretFile = ""
	}
	input, err := nextRecipe.Reuse(provenance.Parameters, parameters, effectiveSecretFile)
	if err != nil {
		return err
	}
	materialization, err := nextRecipe.MaterializeWithInput(recipes.Request{Service: service.Name, Source: service.Source}, input)
	if err != nil {
		return err
	}
	if *dryRun {
		return r.renderRecipeUpgrade(previous, materialization, recipes.WriteResult{ConfigPath: *configPath}, true, *jsonOutput)
	}
	result, err := recipes.Upgrade(*configPath, current, source, provenance, materialization)
	if err != nil {
		return err
	}
	return r.renderRecipeUpgrade(previous, materialization, result, false, *jsonOutput)
}

func (r *Runner) recipeValidate(arguments []string) error {
	fs := flag.NewFlagSet("recipe validate", flag.ContinueOnError)
	fs.SetOutput(r.Err)
	jsonOutput := fs.Bool("json", false, "write machine-readable JSON")
	if err := fs.Parse(normalizeArguments(fs, arguments)); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("recipe validate accepts no positional arguments")
	}
	catalog, err := recipes.Builtin()
	if err == nil {
		err = catalog.Validate()
	}
	if err != nil {
		return err
	}
	if *jsonOutput {
		return writeJSON(r.Out, struct {
			Valid   bool `json:"valid"`
			Recipes int  `json:"recipes"`
		}{Valid: true, Recipes: len(catalog.List())})
	}
	fmt.Fprintf(r.Out, "Validated %d embedded recipes.\n", len(catalog.List()))
	return nil
}

func (r *Runner) renderRecipeMaterialization(materialization recipes.Materialization, result recipes.WriteResult, dryRun, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(r.Out, struct {
			Recipe        recipeSummary      `json:"recipe"`
			Service       config.Service     `json:"service"`
			Provenance    recipes.Provenance `json:"provenance"`
			Created       []string           `json:"created"`
			Updated       []string           `json:"updated"`
			SecretExample string             `json:"secret_example,omitempty"`
			DryRun        bool               `json:"dry_run"`
		}{Recipe: summary(materialization.Recipe), Service: materialization.Service, Provenance: materialization.Provenance, Created: result.Created, Updated: result.Updated, SecretExample: result.SecretExample, DryRun: dryRun})
	}
	fmt.Fprintf(r.Out, "Recipe      %s@%s\nService     %s\nSource      %s\n", materialization.Recipe.ID, materialization.Recipe.Version, materialization.Service.Name, materialization.Source)
	if dryRun {
		fmt.Fprintln(r.Out, "\nDry run: no local files were written.")
		fmt.Fprintf(r.Out, "Would create:\n  %s/%s\n  %s/%s\nWould update:\n  %s\n", materialization.Source, recipes.ComposeFilename, materialization.Source, recipes.ProvenanceFilename, result.ConfigPath)
		return nil
	}
	fmt.Fprintln(r.Out, "Created:")
	for _, filename := range result.Created {
		fmt.Fprintf(r.Out, "  %s\n", filename)
	}
	fmt.Fprintln(r.Out, "Updated:")
	for _, filename := range result.Updated {
		fmt.Fprintf(r.Out, "  %s\n", filename)
	}
	if result.SecretExample != "" {
		fmt.Fprintf(r.Out, "Required secret: create %s from %s and provide non-empty values before planning.\n", materialization.Service.SecretEnvFile, result.SecretExample)
	}
	return nil
}

func (r *Runner) renderRecipeUpgrade(previous recipes.Recipe, next recipes.Materialization, result recipes.WriteResult, dryRun, jsonOutput bool) error {
	if jsonOutput {
		return writeJSON(r.Out, struct {
			From    recipeSummary `json:"from"`
			To      recipeSummary `json:"to"`
			Service string        `json:"service"`
			Updated []string      `json:"updated"`
			DryRun  bool          `json:"dry_run"`
		}{From: summary(previous), To: summary(next.Recipe), Service: next.Service.Name, Updated: result.Updated, DryRun: dryRun})
	}
	fmt.Fprintf(r.Out, "Recipe upgrade %s: %s -> %s\nService: %s\n", previous.ID, previous.Version, next.Recipe.Version, next.Service.Name)
	if dryRun {
		fmt.Fprintln(r.Out, "Dry run: no local files were written.")
		return nil
	}
	for _, filename := range result.Updated {
		fmt.Fprintf(r.Out, "Updated: %s\n", filename)
	}
	fmt.Fprintln(r.Out, "No target was contacted. Run bebop plan to review the ordinary service update.")
	return nil
}

func serviceByName(current config.Config, name string) (config.Service, bool) {
	for _, service := range current.Services {
		if service.Name == name {
			return service, true
		}
	}
	return config.Service{}, false
}
