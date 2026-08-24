# Architecture

## M3 service resources

M3 keeps one planner and adds user-defined service resources to its existing
dependency DAG. A module is Bebop's built-in implementation capability; a
service is one declared resource instance. `modules.Compose` is therefore one
provider for every `[services.NAME]`, not a Go module per application.

```text
strict config + controller source ─> canonical service inputs ─┐
                                                             │
HostFacts <─ Inspector <─ Transport <─ resolver <─ CLI       +─> one Planner -> ordered Plan
  │                   │                                      │                    │
  │                   └─ Docker Compose/runtime state        │                    ├─ render/artifact
  │                                                          │                    │
  └─ relevant snapshot <─────────────────────────────────────┘                    ▼
                                                                      apply lock -> staged deployment -> Compose -> verify
```

`internal/services` owns controller-local source resolution: constrained paths
relative to the config declaration, sorted regular-file manifests, deterministic
archive bytes, source SHA-256, small static Compose checks, project naming, and
the optional keyed secret marker. It has no transport and cannot mutate a
target. `modules.Compose` turns those inputs plus normalized `facts.Service`
into ordinary `plan.Change` values. Its only dependencies are the existing base
data root and Docker/Compose actions when those actions are needed.

The source digest covers non-secret content. A secret environment file is
separate controller input, transferred only as `.bebop-secret.env` with `0600`;
its HMAC is never rendered in facts JSON but participates in the relevant-state
hash and saved-plan input fingerprint. The artifact stores no file or secret
content. See [SERVICES.md](SERVICES.md) for the contract.

On the target, Compose sources live under
`storage.data_root/services/<service>/releases/<source-digest>` and `current` is
an atomic symlink to an active release. Deploy stages from standard input,
validates every expected file digest/mode, asks Compose to validate the staged
project under `env -i` and `--context default`, then atomically activates it.
Service removal uses project-scoped `down --remove-orphans` without `-v` and
removes only `current`; release trees and persistent volume/data boundaries are
preserved. A non-symlink `current` path is blocked rather than treated as
Bebop-owned.

Inspector remains the normal observation boundary. It detects Docker Compose
capability, hashes the active non-secret deployment tree, reads the protected
secret marker only into the internal convergence snapshot, and aggregates
Docker-labeled containers into missing/stopped/starting/running/unhealthy/
unknown runtime plus health status. Module verification performs narrow
immediate checks and a bounded readiness poll; its final reinspection still
flows through the normal planner.

Bebop's execution model is deliberately one-way. M2 adds only controller-side
inventory and portable review artifacts; targets remain ordinary Linux machines
with no Bebop daemon:

```text
inventory alias ─┐
literal target ──┼─> resolver -> Target -> Transport -> Inspector -> HostFacts --+
                 │                                                              +-> Planner -> immutable Plan
host config ─────┘                     strict Config --------------------------+              |
                                                                                                 ├─> render
                                                                                                 └─> canonical artifact
                                                                                                         |
later apply ───────────────────────────────────────────────────────────────────── fresh inspection + drift checks
                                                                                                         |
                                                                                              target flock lease
                                                                                                         |
                                                                                              apply / verify / re-plan
```

`internal/inventory` owns versioned `bebop.hosts.toml`: aliases, safe target
URIs, and relative controller config paths. It writes sorted TOML atomically.
`internal/resolve` turns both aliases and literal target URIs into the existing
`target.Target`, so transport and module execution paths remain singular.

`internal/target` parses only `local` or safe `ssh://user@host[:port]` URIs.
`internal/transport` is the boundary below the domain model. `Local` and `SSH`
both execute an explicit POSIX script request, preserve cancellation and exit
status, and provide file reads. The SSH implementation invokes system OpenSSH
with `BatchMode=yes`; it does not change host-key policy or SSH configuration.

`internal/inspect` is the sole observation layer. It turns `/etc/os-release`,
stable command output, package database state, systemd state, filesystem
metadata, and `tailscale status --json` into `facts.HostFacts`. Modules do not
scatter ad-hoc probes. Raspberry Pi OS (`ID=raspbian`) is normalized as the
`raspberry-pi-os` family rather than being incidentally treated as Debian.

`internal/config` decodes a versioned TOML schema with unknown fields rejected,
applies deterministic defaults, and validates names, enum values, and data-root
paths. Each `internal/modules` capability implements `Plan`, `Apply`, and
`Verify`. Plan has no transport, so it cannot mutate a target. Its changes have
stable IDs, observed and desired state, risk, root requirement, dependencies,
exact script, and verification description. Apply accepts only the reviewed
change and refuses unknown action kinds; it has no separate configuration-to-
shell path.

SSH hardening additionally distinguishes the managed file from effective
configuration. It uses an early `00-bebop.conf`, blocks if an earlier unknown
drop-in could win OpenSSH's first-value precedence, and tests `sshd -T` before
and after replacement.

The planner sorts module registration by module name and uses lexical Kahn
topological sorting for dependencies. Canonical plan JSON has no timestamps,
maps, filesystem traversal results, or network-derived ordering. Its SHA-256
fingerprint covers plan version, target, ordered changes, and ordered warnings;
it excludes its own fingerprint and facts that are not represented in a change.

`internal/apply` rejects blocks, applies the ordered actions, verifies each,
then requests a complete fresh inspection and plan. Remaining executable work
is a verification error. Immediate re-planning before confirmation narrows,
but cannot eliminate, concurrent external changes during apply.

To add a module, normalize new state in `HostFacts`, introduce strict desired
state only when supported, implement the module interface with stable IDs and
dependencies, register it in `modules.Default`, and add deterministic and
transition/idempotence tests. Do not let modules invoke ad-hoc SSH clients or
derive unvalidated shell fragments.

## M2 control-plane boundaries

`internal/preflight` is the shared read-only bootstrap/doctor assessment. It
uses the normal service inspection rather than an alternate SSH client and
reports classified DNS, timeout, refused, host-key, authentication, client,
sudo, and command failures. Inspector facts now include an optional machine ID
and a detected apt/dpkg capability.

`internal/artifact` defines a versioned JSON plan-file contract. Its ordered
canonical body has no timestamps or maps and is SHA-256 hashed. It records the
controller version, endpoint, optional alias, normalized config and fingerprint,
identity, relevant observed-state fingerprint, and complete plan. On a saved
apply, `internal/savedplan` validates schema/self-hash/current config, performs
a fresh normal inspection, checks identity and drift, regenerates the plan, and
passes only that regenerated plan to apply. Artifact scripts are therefore not
an execution authority, even if someone recomputes a self-hash.

Relevant state contains planner/module inputs and plan-warning inputs: OS,
architecture, apt/systemd/privilege state, module facts, firewall/storage
warnings, and data-root metadata. Kernel, memory, free space, timestamps, and
transport timing are excluded. Identity prefers machine ID and conservatively
falls back to hostname plus OS identity when it is unavailable.

`internal/apply` obtains a built-in transport flock lease for the full
apply/verify/replan interval, then evaluates any module-level preconditions
immediately before the action. Local and SSH transports hold
`/run/lock/bebop.lock` through a live process; a controller or SSH crash releases
the kernel lock. This narrows, but does not eliminate, out-of-band TOCTOU races.

`internal/fleet` runs independent read-only work in a bounded worker pool and
writes each result to its original sorted inventory index. `status --all` and
`doctor --all` retain individual errors and render all hosts before returning a
non-zero aggregate result. Fleet mutation is intentionally unsupported.

## M4 persistent-state snapshots

M4 extends a Compose service with explicit logical persistent resources. A
resource is either an authorized Compose named volume or a narrow explicit
absolute bind path. `internal/services` resolves the logical volume declaration
through the project's Compose volume mapping, so a snapshot records `app-data`,
not an implementation-specific source volume name. It also verifies that a
declared volume is mounted by the declared project before backup or restore.

```text
config data declarations -> service deployment -> target resources
                                                    |
                  target stream <- unprivileged Docker helper
                                                    |
                                                    v
controller Repository -> .staging/<id> -> hash + manifest -> snapshots/<id>

completed snapshot -> restore plan -> fresh destination inspection
                      |                   |
                      +-- snapshot digest +-- identity/config/state fingerprints
                                                      |
                                                 target flock
                                                      |
                                       empty-only extraction -> normal convergence
```

`internal/backup.Repository` is a controller-local filesystem repository. It
streams sanitized tar archives through bounded buffers, hashes each stored
archive, seals a deterministic manifest digest, verifies the staging tree, then
atomically publishes it under `snapshots/`. Staging data is never listed as a
snapshot. Completed snapshot files and directories are made read-only; the
repository contains no controller absolute path or secret value.

`internal/backup.Create` uses the existing target flock for the complete
stop-consistent window. The default policy records the service's current runtime
state, stops only a running service, mounts one named volume read-only into a
fixed unprivileged BusyBox helper, streams `tar` to the controller, and restores
the original service state with M3's existing Compose verification. `live` is an
explicit opt-in that does not stop the service and has no application-level
consistency guarantee. Bind paths are captured by the same constrained helper
pattern after conservative target validation.

Restore plans are separate versioned, self-hashed artifacts: a snapshot is an
immutable source fact, not an instruction to mutate a host. A restore plan
stores the snapshot manifest digest, destination target identity, normalized
configuration digest, destination persistent-state fingerprint, and sorted
logical resource mapping. Applying it verifies the snapshot before mutation,
re-inspects the destination under the target flock, blocks non-empty resources
by default, restores through a narrow helper, then delegates deployment/startup
to the existing service planner and apply path. Source and destination runtime
volume names may therefore differ without losing the logical mapping.

## M6 storage placement policy

M6 adds normalized `lsblk --json` and `findmnt --json` topology beneath the
same Inspector/HostFacts boundary. `internal/storage` compares a declarative
resource (mount point, filesystem UUID, optional type/capacity policy) with
that topology. It emits semantic ready/missing/root-spill/wrong-UUID/read-only
state for modules, service placement, backups, restore, doctor, and saved-plan
snapshots; raw device paths and exact free-space telemetry are not desired
state.

```text
storage declaration -> Inspector facts -> storage assessment -> Planner
      │                       │                  │                 │
      │                       └─ UUID/mount facts │                 ├─ storage mount DAG
      └─ fixed Compose variable                   └─ placement guard └─ service/backup/restore
```

The optional storage module has only mount-point, fstab-entry, and mount
actions, ordered before dependent services and covered by the ordinary apply
lock. It has no formatting or device-management action. See [STORAGE.md](STORAGE.md).

## M7 scheduled operations and history

M7 is a controller-side adapter around existing operations. A strict optional
`[maintenance]` policy normalizes a small typed job model (`backup`, `doctor`,
or `update-check`), a portable schedule, optional local-time maintenance
window, retention policy, and deterministic job fingerprint. It is not target
desired state and is deliberately excluded from ordinary convergence-plan
fingerprints.

```text
maintenance TOML -> normalized job -> systemd-user adapter --+-> generated user timer
                              |                                |
                              +-> manual maintenance run <------+ 
                                                               |
                                                   eligibility + local job lock
                                                               |
                           +--------------- existing Bebop operation layers ----------------+
                           |                         |                                      |
                        backup.Create             preflight.Run                    apt simulation
                           |                         |                                      |
                     target apply flock       read-only SSH inspection       optional locked apt update
                           |                                                                |
                           +---------------- typed result -----------------------------------+
                                                               |
                                                    immutable local history record
```

The Linux systemd adapter generates one `Type=oneshot` user service and one
`Persistent=true` timer for each enabled job. `ExecStart` is a correctly quoted
absolute Bebop executable plus `maintenance run --scheduled`, absolute config,
absolute inventory, and safe job name; it does not use a shell wrapper, copy
secrets, or rely on scheduler `PATH`/cwd. The unit content is the scheduler
fingerprint: status compares exact desired bytes to detect policy, project,
binary, and manual-edit drift. Installation/reconciliation is explicit and
only manages files with Bebop's owned marker.

`internal/maintenance.Runner` is the common manual/scheduled entrypoint. It
checks enabled/window policy before target access, holds a controller-local
advisory lock only for the selected job, delegates to the existing target
operation, then atomically writes a bounded per-run JSON history record. The
target apply flock remains the mutation authority for backups and optional
metadata refresh; read-only jobs do not acquire it. History is provenance, not
correctness state.

Scheduled backup passes M7 job provenance to M4's existing immutable manifest.
After a successful verified snapshot only, `backup.Repository` deterministically
selects and safely deletes older verified snapshots with the same logical
job/target/service scope. Manual snapshots and another job's snapshots carry no
matching scope and cannot be selected. A corrupt candidate is retained and
reported rather than automatically removed.

## M8 events and notifications

M8 is strictly downstream from operation semantics. `backup.Create`,
`preflight.Run`, Apt simulation, storage assessment, and Compose health do not
know about sinks or providers. Maintenance first writes its normal immutable
record, projects its safe typed outcome into `internal/notification.Operation`,
then derives event candidates and evaluates controller-local policy while the
same selected-job lease remains held.

```text
typed maintenance outcome
          |
          +--> immutable M7 history
          |
          v
  EventFactory -> normalized Event (ID + issue fingerprint)
          |
          v
notification state lease -> active issue/dedupe/cooldown/recovery -> routes -> sinks
          |                                                       |              |
          +-> atomic state.json + delivery records                +-> file / HTTPS POST
```

Events have a unique occurrence ID and a separate SHA-256 issue fingerprint.
The latter contains only stable logical domain/target/job/service/resource/
category data, allowing repeat suppression across controller restarts without
including timestamps, raw messages, machine IDs, paths, or secrets. Recovery
is a state transition: a successful observation removes a matching active
issue; a recovery is sent only to a route that successfully received its active
failure.

`internal/notification` owns policy routing, state, delivery history, safe
file append, and generic webhook delivery. It has no target transport and no
provider-specific operation code. Webhook secrets resolve at delivery from the
controller environment and never enter systemd units, events, history, local
state, or error output. A delivery result is returned separately from the
maintenance operation result, so delivery failures do not retry or invalidate
the operation.

The shared `internal/lease` implementation uses process-held OS locks. Unix
uses `flock`; Windows uses `LockFileEx`. A pathname can remain after a crash,
but kernel lock ownership is released, so future maintenance/state writers can
reacquire it. This is controller-local coordination, not a distributed lock.

## M5 deterministic recipe authoring

M5 deliberately sits **before** normal configuration and source resolution; it
does not add another target, planner, deployment, backup, or execution path.
`internal/recipes` embeds a small versioned corpus and owns strict metadata
validation, typed scalar parameter normalization, restricted YAML-scalar
rendering, source/provenance materialization, and provenance-aware upgrades.

```text
embedded recipe corpus -- strict schema --> typed recipe + fingerprint
                                              |
recipe init / upgrade -- typed parameters ---> restricted rendered Compose
                                              |
                                        normal bebop.toml + services/<name>/
                                              |
                                              v
                        existing services.Resolve -> Planner -> saved plan -> apply
                                              |
                                              +-> M3 lifecycle / M4 logical data backup
```

The corpus filesystem is compiled into the controller binary. It is deterministic
and offline: no remote catalog lookup, registry API, plugin loader, arbitrary
template expression, target probe, or target mutation is involved in recipe
commands. Recipe image and architecture metadata are validated locally; for an
intact generated source, normal planning/preflight classifies the recipe against
fresh HostFacts architecture before a service action can be applied.

`recipe init` writes a normal config service declaration and ordinary Compose
source. Stateful recipe data compiles directly to M4 logical data declarations;
recipe secrets compile only to M3's `secret_env_file` reference. Recipe
provenance is generated metadata with a schema/self-fingerprint, recipe
fingerprint, normalized non-secret parameters, secret names/references, and
rendered Compose digest. It is not desired-state authority and carries no
secret value, controller absolute path, host identity, target script, or target
state.

An upgrade requires valid provenance and unchanged generated source, validates
parameter and service-data/secret compatibility, stages a new local source tree,
and replaces it atomically. M3/M4 still own all target behavior. Deleting
provenance intentionally ejects the source to generic user-managed Compose;
normal service planning keeps working, while recipe management no longer claims
authority to overwrite it.
