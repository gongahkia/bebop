# Scheduled operations and unattended maintenance

M7 lets a controller repeat a narrow set of existing Bebop operations over
time. It is not a Bebop daemon, target agent, cron-command runner, automatic
convergence engine, backup product, or notification service. Targets remain
ordinary agentless Linux machines reached through the existing OpenSSH transport.

## Policy

Maintenance policy is optional, strict version-1 TOML in a file-backed
`bebop.toml`. It contains no secret values. An inventory alias uses the target
config associated with that host when one exists; otherwise the policy file is
also the operation's target config. A backup service must be declared in that
resolved target config.

```toml
[maintenance]
version = 1
history_dir = ".bebop/history" # controller-relative, the default
history_max_entries = 500       # the default

[[maintenance.jobs]]
name = "nightly-passwords"
type = "backup"
target = "pi"                  # inventory alias, local, or safe literal target
service = "passwords"          # required only by backup
schedule = "daily@03:00"
enabled = true                  # default

[maintenance.jobs.window]
start = "02:00"
end = "05:00"

[maintenance.jobs.retention]
keep_last = 7

[[maintenance.jobs]]
name = "weekly-doctor"
type = "doctor"
target = "pi"
schedule = "weekly@sun@08:00"

[[maintenance.jobs]]
name = "update-awareness"
type = "update-check"
target = "pi"
schedule = "daily@09:00"
refresh_metadata = false
```

Job names are safe lowercase identifiers. The only types are `backup`,
`doctor`, and `update-check`; unknown fields and types are rejected. There is
no `command`, `apply`, `restore`, recipe upgrade, generic restart, image update,
or package upgrade job.

Schedules are portable policy, not raw systemd or shell syntax:

- `hourly`
- `daily@HH:MM`
- `weekly@mon@HH:MM` through `weekly@sun@HH:MM`

M7 uses the controller's local timezone. It does not infer a target timezone
and currently has no per-job IANA timezone field. Native systemd handles local
DST behavior. Job fingerprints contain normalized job policy, never time,
next-run state, project paths, or secret data.

## Windows and missed runs

A window is optional. Its start is inclusive and end is exclusive; `23:00` to
`03:00` crosses midnight. Eligibility is checked when `maintenance run` starts,
not repeatedly during a long backup. A job that starts inside a window may
finish after it. A scheduled or manual invocation outside its window records
`skipped` with `outside-window`, performs no operation, and exits successfully.
Manual operators may use `--ignore-window`; generated scheduler invocations
cannot.

Linux timers use `Persistent=true`. This may cause one native catch-up
invocation after a controller was unavailable, but M7 never queues an
unbounded backlog and the runtime window check remains authoritative.

## Commands

```sh
bebop maintenance list [--config bebop.toml] [--json]
bebop maintenance show JOB [--config bebop.toml] [--inventory FILE] [--json]
bebop maintenance run JOB [--config bebop.toml] [--inventory FILE] [--ignore-window] [--json]
bebop maintenance install [--config bebop.toml] [--inventory FILE] [--dry-run] [--json]
bebop maintenance status [--config bebop.toml] [--inventory FILE] [--json]
bebop maintenance history [JOB] [--config bebop.toml] [--json]
bebop maintenance uninstall --yes [--config bebop.toml] [--inventory FILE] [--json]
```

`run` is the stable manual and generated execution entrypoint. It resolves the
typed job, checks policy, obtains a local per-project/job lease, invokes the
existing operation layer, and writes history. The `--scheduled` flag exists
only for generated systemd units. `maintenance list`, `show`, `status`, and
`history` do not contact targets or create history directories.

## Linux scheduler adapter

M7 supports Linux controllers with a reachable systemd **user** manager. It
uses the controller user configuration directory (normally
`~/.config/systemd/user`) and writes one owned service and timer per enabled
job:

```text
bebop-maintenance-nightly-passwords.service
bebop-maintenance-nightly-passwords.timer
```

The service uses a direct, correctly escaped `ExecStart` for the absolute
current Bebop binary and `maintenance run --scheduled`; it captures canonical
absolute config, inventory, and working-directory paths. It has no shell
wrapper, `PATH` dependency, secret environment file, SSH password, or sudo
password. Normal OpenSSH `BatchMode=yes` and target-side `sudo -n` keep a timer
from waiting interactively.

`maintenance install --dry-run` renders deterministic reconciliation. A normal
install writes owned units atomically, reloads the user manager, enables timers,
and removes only obsolete units still marked as Bebop-owned. Re-running it is
idempotent. `maintenance status` compares exact desired unit content and shows
`current`, `missing`, `stale`, `disabled`, or `unit-error`; edits, a changed
schedule, a moved config/project, or a moved binary are stale until an explicit
install. `uninstall --yes` disables/removes only marked Bebop units and leaves
policy, history, snapshots, and unrelated user units intact.

macOS and Windows scheduler installation/status/uninstall report the adapter as
unsupported in M7. Controller cross-builds remain supported; manual maintenance
execution is available on Unix controllers where the underlying operation and
local crash-safe lease are available. M7 does not claim a Windows scheduler
adapter.

## Typed operations

`backup` calls M4 `backup.Create` directly, retaining source identity, storage
placement guards, target apply locking, `stop`/`live` consistency, service
runtime restoration, helper isolation, and snapshot verification. It does not
invoke the CLI as a subprocess. `doctor` calls the normal read-only preflight
assessment and records pass/warn/fail counts. `update-check` inspects Debian
apt availability with `apt-get -s upgrade`; available updates are information,
not failure and never cause installation.

`refresh_metadata = true` is explicit. It performs `apt-get update` only,
under the existing target mutation lock, before the simulation. It never runs
`apt upgrade`, `full-upgrade`, package installation, image update, or reboot.
Without refresh, history reports availability from whatever target package
metadata was already present. Security counts are `known` only when the apt
simulation exposes a security origin for every available update; otherwise the
classification is `unknown` rather than a guess.

## Retention

`retention.keep_last` is valid only for a backup job. After a newly created
snapshot has completed and verified, Bebop considers only verified snapshots
with the same maintenance job provenance scope: job name, resolved target, and
selected service. It orders by creation time and snapshot ID, then deletes
oldest excess snapshots through the repository's validated deletion API.
Manual backups have no maintenance provenance and are preserved; other jobs,
targets, services, staging directories, malformed directories, and corrupt
snapshots are never selected. A corrupt matching snapshot is kept and produces
a warning. A failed backup never runs retention. If retention deletion fails,
the verified new snapshot is retained and the run is a warning/non-zero
scheduler invocation.

## History and concurrency

M7 writes bounded immutable per-run JSON files below `history_dir`; the default
is `.bebop/history`. Each record has schema version, run ID, job/fingerprint,
operation, target reference, origin, window override, timestamps, normalized
result (`success`, `warning`, `failure`, or `skipped`), and typed summary. Raw
stderr and arbitrary error text are intentionally excluded, so scheduler logs
remain in `journalctl --user -u bebop-maintenance-NAME.service`.

The history directory must be a real controller directory that is not group- or
world-writable; new directories are created with restrictive user permissions.

History is provenance, not truth: deleting it does not affect targets,
snapshots, eligibility, locks, or recovery. Per-job controller advisory leases
under `.bebop/maintenance/locks` prevent duplicate manual/timer runs and are
released by the kernel if a process exits. Different jobs are not globally
serialized. Existing target flock ownership remains authoritative whenever a
backup or explicit metadata refresh mutates target state.
