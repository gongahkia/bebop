# Deterministic service recipes

M5 recipes are small, reviewed controller-side authoring inputs for the normal
M3 Compose service model. They do not introduce target-side recipe logic,
plugins, a marketplace, a remote registry, arbitrary hooks, or an alternate
deployment system. Every built-in recipe is embedded in the Bebop binary and is
therefore available offline.

## Corpus and inspection

The bundled corpus currently contains `whoami`, `uptime-kuma`, `vaultwarden`,
and `forgejo`. A recipe has a stable ID and an independently versioned recipe
version. That version is distinct from the pinned application image version.

```sh
bebop recipe list
bebop recipe show vaultwarden
bebop recipe show whoami --version 1.0.0
bebop recipe validate
```

`list`, `show`, and `validate` have `--json` where useful. `recipe validate`
strictly parses the complete embedded corpus and is a controller-only check;
it never resolves a target or invokes Docker.

Each recipe declares its stable ID/version, description, application/image
versions, supported target architectures, health expectation, typed parameter
schema, logical persistent data resources, and required secret environment
keys. Built-in images must have a non-`latest` explicit tag or digest. Recipes
support Linux `amd64` and/or `arm64`; planning blocks an intact recipe-managed
service on an unsupported inspected target architecture before mutation.

## Materialization

Materialize a recipe into ordinary user-visible Bebop configuration and source:

```sh
bebop recipe init uptime-kuma \
  --service status \
  --config bebop.toml \
  --param port=3001

bebop recipe init vaultwarden \
  --service passwords \
  --config bebop.toml \
  --secret-file secrets/passwords.env \
  --param domain=passwords.home.arpa
```

The default output directory is `services/<service>`, adjustable only with a
safe controller-relative `--output` path. `--dry-run` renders without writing.
`--param name=value` is repeatable. The schema accepts only `string`,
`integer`, `boolean`, `enum`, `port`, and constrained POSIX `path` values;
unknown, duplicate, missing required, invalid range, and invalid enum values
are rejected before writing local files.

For a service named `status`, initialization appends an ordinary declaration
equivalent to:

```toml
[services.status]
type = "compose"
source = "services/status"
state = "running"
health_timeout = "2m"
```

It writes `services/status/compose.yaml` and
`services/status/bebop.recipe.json`. Stateful recipes also append normal
`[[services.status.data]]` resource declarations and `[services.status.backup]`
settings. From that point `bebop plan`, saved plans, `apply`, `status`,
`doctor`, `backup`, and restore use the same generic M3/M4 code paths as a
hand-authored Compose service.

No target connection occurs during initialization or upgrade. Review the
resulting config/source like any other change, then run normal `bebop plan`.

## Secrets

Recipe secret declarations name an environment key but never take a secret
value. A secret-bearing init requires `--secret-file`, writes a mode-`0600`
`<secret-file>.example`, and does **not** create the real secret file. Copy the
example locally, fill it outside version control, and use the existing M3
`env_file: .bebop-secret.env` behavior. Recipe provenance, Compose source,
plan artifacts, JSON, and normal logs contain secret references and names only;
they never contain secret values.

## Provenance and upgrades

`bebop.recipe.json` is a schema-versioned generated provenance record. It
contains recipe ID/version/fingerprint, normalized non-secret parameters,
secret file reference and secret names, rendered Compose SHA-256, and a
self-fingerprint. It contains no target identity, target state, secret value,
or controller absolute path.

An upgrade is explicit and uses only a version already bundled in the binary:

```sh
bebop recipe upgrade echo --config bebop.toml --to 1.1.0
```

Bebop first validates the provenance self-fingerprint, checks that the source
contains only its expected generated files and still matches the recorded
Compose hash, re-validates retained typed parameter values against the next
newer version, and requires identical service state/verification, logical
persistent-resource, and secret-file contracts. It stages and atomically replaces the local generated source only
after those checks. It does not edit the target or silently rewrite the service
declaration. A dry run performs the same readiness checks.

If generated source needs hand edits or local extra files, recipe upgrades
refuse and tell the operator to remove `bebop.recipe.json`. Removing that file
is deliberate ejection: the configuration/source remain a valid ordinary
generic M3 service, but no later recipe upgrade claims authority over it.

## Rendering and compatibility

Recipe metadata and Compose templates are strictly parsed during corpus load.
Templates are parsed as YAML and only declared non-secret parameter placeholders
inside string scalar values are replaced; rendering then validates the resulting
Compose structure and expected pinned image set. Values cannot introduce YAML
keys, command fragments, templates, conditionals, or new image references.

Recipe `health` metadata documents whether running containers alone are the
expectation or an image healthcheck is expected. Actual runtime verification is
still M3's Compose inspection: healthcheck-bearing containers must become
healthy, while images without healthchecks report `no-healthcheck` rather than a
made-up healthy result.

The archived/target service is portable only to the extent already promised by
M3/M4. Recipe images publish the listed architectures, but their applications,
numeric ownership assumptions, data formats, and secret values remain the
operator's responsibility. Persistent data migration maps by the normal logical
resource name, never by a source runtime Docker volume name.
