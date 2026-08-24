# Compose services

M3 provides a generic deterministic Compose resource. Hand-authored sources
remain the base model. M5 additionally supplies a small embedded set of
deterministic recipe authoring inputs, but it adds no remote registry,
marketplace, plugin runtime, arbitrary application version policy, or alternate
service runtime. A materialized recipe becomes the same normal Compose source
and service declaration described here.

## Declaration

Services are strict entries in the complete desired-state configuration:

```toml
[services.hello]
type = "compose"
source = "services/hello"
state = "running"
health_timeout = "2m"
```

`type` must be `"compose"`. Service names are lowercase letters, numbers, and
hyphens, start with a letter, and are limited to 63 characters. `state` is one
of `running`, `stopped`, or `absent`; it defaults to `running`.
`health_timeout` defaults to `2m` and must be between one second and 30
minutes.

`source` is a controller-relative path resolved from the directory containing
the `bebop.toml` that declares it. It cannot be absolute or escape that
directory. A source must contain exactly one root-level `compose.yaml`,
`compose.yml`, `docker-compose.yaml`, or `docker-compose.yml`.

## Storage-relative bind paths (M6)

A path resource may retain M4's explicit absolute `path`, or use a declared
M6 storage resource plus a clean relative path. For `storage = "bulk"` and
`path = "media"`, the Compose source should bind `${BEBOP_DATA_MEDIA}`;
Bebop provides that fixed value from the logical data declaration while
validating and running Compose. This preserves identical source when another
host maps `media` to a different storage name. `${BEBOP_STORAGE_BULK}/media`
remains available for direct host-local placement. These are the only supported
bind-path interpolations. They keep placement out of service source and block
deployment/start if UUID, mount, writeability, or configured capacity policy is
not ready. See [STORAGE.md](STORAGE.md).

## Recipe-generated services (M5)

`bebop recipe init ID --service NAME` creates a normal declaration and source
directory, then normal `plan`/`apply` owns target mutation. See
[RECIPES.md](RECIPES.md) for the local catalog, typed parameters, secret
templates, provenance, and upgrades. Recipe output has no privileged or SSH
capability of its own.

Generated `bebop.recipe.json` records provenance so `recipe upgrade NAME --to
VERSION` can refuse manual source drift and incompatible persistent-data/secret
changes. It is not required for normal service operation: remove it to eject the
service to generic user-managed Compose source. Do not edit generated source
and expect a recipe upgrade to overwrite it.

Source traversal is deterministic and sorted. Bebop accepts regular files only,
rejects symlinks and special files, retains just the executable bit (`0644` or
`0755`), and hashes bytes without newline normalization. It rejects `.git` and
`node_modules` directories so a deployment does not accidentally absorb a
repository or dependency tree. The hard guardrails are 10,000 files and 256
MiB. M3 does not implement `.bebopignore`; place large/generated content
outside the source tree.

Compose static validation deliberately remains narrow. It rejects `build`,
profiles, `extends`, YAML aliases, and non-string `env_file` forms. Use explicit
image references. Bebop detects duplicate fixed host ports across declared
services before connecting, but it does not claim a complete Compose semantic
parser or detect collisions with unrelated Docker projects.

## Deployment and lifecycle

For `storage.data_root = "/srv/bebop"`, service `hello` has this target layout:

```text
/srv/bebop/services/hello/
  releases/<source-sha256>/     # replaceable non-secret deployment source
  current -> releases/<sha256>  # the sole active deployment pointer
```

`deploy` streams a controller-created, validated archive through the ordinary
transport to a staging directory. Bebop validates its expected file modes and
digests, invokes `docker compose config -q` with an explicit environment,
activates the release atomically through `current`, then reconciles only that
project. A release with unexpected or modified files is replaceable deployment
content; a `current` path that is not a Bebop release symlink is blocked rather
than overwritten.

The states mean:

- `running`: stage/restore changed deployment input, then run `docker compose up -d --remove-orphans` and verify readiness.
- `stopped`: keep/repair the deployment, then run `docker compose stop`; no deployment or volume is deleted.
- `absent`: run `docker compose down --remove-orphans` when an active Compose file exists, without `-v`; otherwise remove containers only by the deterministic project label. It removes `current` but retains release trees, named volumes, and bind-mounted data.

There is intentionally no aggressive release cleanup, automatic image pull,
volume deletion, data-root deletion, or generalized rollback. Relative bind
mount paths are rejected because an application could write persistent data into
a replaceable release tree. Use a named volume or a deliberate absolute target
path (for example `/srv/bebop/data/hello`) rather than treating deployment
releases as persistent data.

Project names are deterministic from `server.name` and service name, with a
bounded hash. Every Compose command specifies this project name and its active
deployment directory. Therefore service A cannot use service B's Compose
namespace through normal Bebop operations.

## Docker and health

Services require Docker Engine and Docker Compose v2. The existing Docker
module remains the only installer: if apt advertises `docker-compose-plugin` or
`docker-compose-v2`, it can plan installation after the engine/service actions.
Otherwise the service action is blocked. Bebop does not install Docker from a
convenience script or add external Docker repositories.

Compose commands run with `env -i`, a fixed safe PATH, `HOME=/root`, and
`docker --context default`. Ambient controller or target `DOCKER_HOST` and
`DOCKER_CONTEXT` are excluded.

Runtime inspection uses Docker project labels and container state. A service is
`missing`, `stopped`, `starting`, `running`, `unhealthy`, or `unknown`.
`running` is distinct from health: when a healthcheck exists all relevant
containers must become `healthy` before the bounded timeout; a workload with no
healthcheck is reported as `running` with `no-healthcheck`, not falsely as
healthy. `unhealthy`, missing, or timeout readiness makes apply fail.

## Sources, secrets, and saved plans

The source manifest is sorted by logical path and hashes `mode`, file digest,
and path. Its SHA-256 is the non-secret deployment digest. Remote inspection
recomputes that same digest from `current`, so a manually changed Bebop-managed
Compose file creates a corrective semantic update. A manually stopped container
creates a start/reconcile action without copying unchanged source.

To supply a minimal secret environment file:

```toml
[services.hello]
type = "compose"
source = "services/hello"
secret_env_file = "secrets/hello.env"
```

The Compose file must reference `env_file: .bebop-secret.env`. The controller
transfers that file into the active release with `0600`. Bebop never writes the
value into a plan, artifact, report, history, command rendering, or diagnostic.
It creates a controller-local random HMAC key at
`.bebop/cache/secret-hmac.key` (mode `0600`) and records only the resulting HMAC
marker. The marker is safe against direct low-entropy digest comparison without
the controller key. Its target copy is root-only and is omitted from non-secret
deployment hashes.

Saved plans record a service-input fingerprint built from the source digest and
that keyed secret marker. Before `apply --plan`, Bebop resolves controller
inputs and requires this fingerprint to match before opening a target
connection. A changed source or secret therefore requires a new plan. Losing the
local HMAC key is safe but makes old secret-bearing plans stale. This is a
minimal secret-reference model, not a secret manager; users must keep the
secret file and controller cache out of Git and appropriate backups.

M3 does not promise transactional deployment or rollback. The existing target
apply lock and immediate deployment preconditions narrow races, but another
actor can still modify Docker or files between checks. Reinspection and the next
plan report any resulting divergence.

## Persistent data declarations (M4)

Compose storage use is not backup authorization. Add `[[services.NAME.data]]`
only for named volumes or deliberate absolute application paths that Bebop may
back up and restore. Volume declarations name a mounted top-level Compose key;
they map by the resource's `name`, not a host-specific Docker volume name.
Path declarations are deliberately restricted to safe application-data roots.
`[services.NAME.backup].consistency` accepts `stop` (default) or explicit
`live`. Service sources and `secret_env_file` inputs remain controller-side
deployment inputs and are never part of M4 data snapshots. See [BACKUPS.md](BACKUPS.md).

Recipe-declared persistent resources compile to exactly these same M4
declarations. They remain opt-in backup authorization, not an instruction to
back up every Docker volume used by an application.

## Scheduled service backups (M7)

Maintenance jobs name an ordinary materialized service, not a recipe ID. A
scheduled backup therefore uses the same declared data resources, `stop`/`live`
consistency policy, M4 target lock, and health verification described above.
M7 does not schedule Compose apply, recipe upgrades, generic restarts, image
updates, or arbitrary service commands. A service selected by a maintenance
backup must still be declared in the target's resolved config.
