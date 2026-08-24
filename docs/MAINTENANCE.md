# Scheduled operations and unattended maintenance

M7/M9 lets a controller repeat a narrow set of existing Bebop operations over
time. It is not a Bebop daemon, target agent, cron-command runner, automatic
convergence engine, backup product, or persistent notification service. M8
adds one bounded, downstream notification evaluation per invocation. Targets
remain ordinary agentless Linux machines reached through the existing OpenSSH
transport.

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

Schedules are portable policy, not raw systemd, launchd, or shell syntax:

- `hourly`
- `daily@HH:MM`
- `weekly@mon@HH:MM` through `weekly@sun@HH:MM`

Maintenance uses the controller's local timezone. It does not infer a target
timezone and currently has no per-job IANA timezone field. The native scheduler
handles local daylight-saving behavior. Job fingerprints contain normalized job
policy, never time, next-run state, project paths, native artifact bytes, or
secret data.

## Windows, missed runs, and native timing

A window is optional. Its start is inclusive and end is exclusive; `23:00` to
`03:00` crosses midnight. Eligibility is checked when `maintenance run` starts,
not repeatedly during a long backup. A job that starts inside a window may
finish after it. A scheduled or manual invocation outside its window records
`skipped` with `outside-window`, performs no operation, and exits successfully.
Manual operators may use `--ignore-window`; generated scheduler invocations
cannot.

Linux systemd timers use `Persistent=true`. This may cause one native catch-up
invocation after a controller was unavailable. macOS uses `StartInterval=3600`
for `hourly` and `StartCalendarInterval` for `daily` and `weekly`; launchd owns
the behavior after sleep, wake, logout, or a missed calendar time. Bebop never
creates its own catch-up queue or unbounded backlog on either platform. The
runtime window check remains authoritative whenever an invocation starts.

Windows has no native scheduler adapter in M9. `maintenance run` and its
crash-safe controller lease remain available where the underlying operation is
supported, while `install`, `status`, and `uninstall` report the scheduler as
unsupported.

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
only for generated native scheduler artifacts. `maintenance list`, `show`, `status`, and
`history` do not contact targets or create history directories.

## Native scheduler adapters

Scheduler selection is centralized in `internal/maintenance`: Linux resolves
to the systemd-user adapter, macOS resolves to the launchd LaunchAgent adapter,
and unsupported controller platforms fail clearly without attempting to emulate
another scheduler. All artifacts invoke the same direct Bebop command:

```text
<absolute-bebop> maintenance run --scheduled --config <absolute-config> --inventory <absolute-inventory> <job>
```

The executable, config, inventory, project root, and controller home are
canonical absolute paths captured at installation. Bebop rejects a temporary
or `go run`-style executable path instead of installing an artifact that is
likely to disappear. Job names remain constrained identifiers. The artifact
contains no shell wrapper, secret environment file, SSH password, or sudo
password. Both adapters set only a narrow system path
`/usr/bin:/bin:/usr/sbin:/sbin`, allowing the existing OpenSSH transport to
find `/usr/bin/ssh`; normal `BatchMode=yes` and target-side `sudo -n` keep a
scheduled run from waiting for input.

### Linux systemd user timers

Linux requires `systemctl --user`, a reachable user manager, a safe user unit
directory (normally `~/.config/systemd/user`), and `/usr/bin/ssh`. For every
enabled job the adapter writes a `Type=oneshot` service and a
`Persistent=true` timer named like:

```text
bebop-maintenance-<project-id>-nightly-passwords.service
bebop-maintenance-<project-id>-nightly-passwords.timer
```

`<project-id>` is a deterministic short SHA-256-derived identifier of the
canonical project root. It prevents two projects owned by one controller user
from claiming each other's scheduler files and does not reveal their paths.
The service has direct escaped `ExecStart` arguments and `WorkingDirectory`;
it does not use a shell. Install atomically writes changed files, runs
`daemon-reload`, enables timers, and confirms their presence with
`list-timers`. Reinstalling unchanged policy is a no-op.

M9 recognizes an old M7 `bebop-maintenance-<job>` service only when its managed
content binds to this exact canonical project root and config path. Status
reports it as stale and `maintenance install` migrates it to the project-scoped
names. A marker alone never authorizes claiming a different project's legacy
timer.

### macOS launchd LaunchAgents

macOS requires the current graphical user domain (`gui/<uid>`), `launchctl`,
`plutil`, `/usr/bin/ssh`, and a safe real `~/Library/LaunchAgents` directory.
For every enabled job Bebop writes one deterministic plist named and labelled
like:

```text
~/Library/LaunchAgents/com.bebop.<project-id>.maintenance.nightly-passwords.plist
com.bebop.<project-id>.maintenance.nightly-passwords
```

The plist uses `ProgramArguments`, `WorkingDirectory`, `HOME`, a narrow `PATH`,
and `ProcessType=Background`. It has neither `KeepAlive` nor `RunAtLoad`; one
schedule event starts one finite `maintenance run --scheduled` process. Hourly
policy compiles to `StartInterval=3600`; daily and weekly policy compile to a
single `StartCalendarInterval` dictionary using launchd weekday values
(`0` Sunday through `6` Saturday). The XML is generated deterministically,
validated before installation with `plutil -lint`, atomically replaced, then
loaded with `launchctl bootstrap`. Changed or removed artifacts are first
booted out, which is launchd's required reconfiguration boundary and can
interrupt a native invocation; the shared per-job lease still prevents a
second Bebop operation from overlapping a surviving/manual one.

`maintenance status` compares exact plist bytes plus launchd loaded state. It
reports `current`, `missing`, `stale`, `disabled`, or `scheduler-error` with
the backend, native label, installed/loaded fields, and desired/actual artifact
digests in JSON. `maintenance install --dry-run` shows stable install/update/
remove actions without changing the scheduler. A normal install and
`maintenance uninstall --yes` reconcile only regular files carrying Bebop's
marker, matching project-scoped label, and exact config path. They never scan
or delete other LaunchAgents.

### Environment and notifications

Native artifacts intentionally do not copy M8 webhook URL or authorization
values. Launchd does not inherit an interactive shell's complete environment,
so macOS operators who use webhook notifications must arrange the referenced
environment variables in their user launchd domain using their own secure login
or secrets mechanism. `bebop notification status` reports whether the current
controller process can resolve each configured reference, but cannot prove a
future native LaunchAgent will receive it. This limitation is explicit rather
than a reason to serialize secret values into a plist or unit.

`maintenance install --dry-run` renders deterministic reconciliation. A normal
install writes only safe owned artifacts and verifies native loading. Re-running
it is idempotent. A changed schedule, policy, binary path, config path, project
root, or manual edit is stale until explicit reinstall. `uninstall --yes`
preserves policy, history, snapshots, and unrelated user scheduler state.

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
stderr and arbitrary error text are intentionally excluded. Native scheduler
logs remain in `journalctl --user -u bebop-maintenance-<project-id>-NAME.service`
on Linux or the normal macOS unified log / `launchctl print` diagnostics for a
LaunchAgent label.

The history directory must be a real controller directory that is not group- or
world-writable; new directories are created with restrictive user permissions.

History is provenance, not truth: deleting it does not affect targets,
snapshots, eligibility, locks, or recovery. Per-job controller leases under
`.bebop/maintenance/locks` prevent duplicate manual/timer runs. They are OS
locks (`flock` on Unix and `LockFileEx` on Windows), so a stale pathname is
harmless after process death. Different jobs are not globally serialized.
Existing target flock ownership remains authoritative whenever a backup or
explicit metadata refresh mutates target state.

## Events and notifications (M8)

When `[notifications]` is enabled, `maintenance run` writes its normal M7
record first, then derives secret-safe operational events and evaluates the
local M8 policy before releasing the selected job lease. A delivery failure is
reported separately and does not change the underlying maintenance result,
maintenance history result, snapshot validity, or scheduler exit behavior. A
native scheduler artifact still contains only the normal `maintenance run
--scheduled` arguments plus `HOME` and a narrow system `PATH`; it never embeds
webhook URLs, headers, or notification secrets.

Scheduled runs are eligible for notification policy by default. Manual runs are
quiet unless `notifications.notify_manual = true`. See
[NOTIFICATIONS.md](NOTIFICATIONS.md) for routes, recovery, cooldowns, sinks,
and delivery history.
