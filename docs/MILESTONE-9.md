# M9 — Portable Native Controller Schedulers

M9 makes the existing M7 typed-maintenance policy portable across supported
controller schedulers without changing target semantics. Bebop still has no
daemon: a native scheduler starts a finite `maintenance run --scheduled`
process, and the existing runner remains responsible for policy, leases,
history, notifications, SSH transport, target locks, and operation results.

## Delivered boundary

- `internal/maintenance.SchedulerAdapter` centralizes controller platform
  selection. Linux uses the retained systemd-user implementation; macOS uses a
  launchd LaunchAgent implementation; unsupported controllers return a
  structured unsupported capability instead of attempting an emulation.
- Deterministic project-scoped native identities derived from the canonical
  project root. Linux names service/timer pairs
  `bebop-maintenance-<project-id>-<job>`; macOS uses
  `com.bebop.<project-id>.maintenance.<job>` labels and plist names beneath the
  current user's `~/Library/LaunchAgents`.
- Direct, shell-free absolute `bebop maintenance run --scheduled --config ...
  --inventory ... JOB` invocation. The native environment contains only the
  current home where required and a narrow standard path for `/usr/bin/ssh`.
  It never captures interactive shell state or notification secrets.
- A deterministic XML plist renderer with `StartInterval=3600` for hourly
  policy and `StartCalendarInterval` dictionaries for daily/weekly policy;
  `ProgramArguments`, `WorkingDirectory`, `HOME`, and safe `PATH`; no
  `KeepAlive`, `RunAtLoad`, shell, or log-file redirection.
- Explicit, idempotent install/reconcile/status/uninstall lifecycle. launchd
  artifacts are XML-checked, `plutil -lint` checked, atomically written, and
  bootstrapped in `gui/<uid>`; systemd artifacts are atomically written,
  daemon-reloaded, enabled, and checked with `list-timers`.
- Exact desired/actual artifact digest and native state diagnostics with
  backend/native identity in JSON. A manual edit, policy/schedule, path,
  binary, project, load, or enablement change is visible as drift.
- Conservative M7 migration: only a legacy unscoped systemd artifact whose
  managed service content proves the exact current project root and config is
  marked stale and removed during explicit installation.

## Safety boundary

M9 owns controller artifacts only. It does not install a daemon or agent, touch
target scheduler configuration, add cron, add a macOS LaunchDaemon, add Windows
Task Scheduler, create a generic command job, schedule apply/restore/upgrade,
weaken SSH BatchMode or `sudo -n`, or change M0-M8 saved-plan, backup, service,
storage, secret, notification, or locking behavior.

Artifact ownership requires the project-scoped name, Bebop marker, a matching
native identity, and matching config binding. Reconciliation refuses symlinks
and non-regular artifact files and never scans/deletes unrelated scheduler
state. Generated arguments and XML are constrained/escaped; native calls use
structured argv and bounded contexts. `maintenance install` rejects a temporary
controller binary so a plist/unit cannot silently point at a vanished `go run`
build.

launchd requires `bootout` before an updated or obsolete agent can be
reconfigured. That native operation may interrupt a currently running agent;
the common per-job lease remains the process-overlap safeguard, and any failed
recovery is reported rather than treated as a successful reconciliation.

M8 notification references remain environment-only. They are deliberately not
copied to a systemd unit or plist. `notification status` reports current-process
reference availability but cannot prove that a future macOS LaunchAgent has the
same environment.

## Validation boundary

Focused unit tests cover portable schedule compilation, all launchd weekdays,
an exact deterministic plist golden, XML escaping, no-shell/no-keepalive
properties, drift from policy/binary/project/manual edits, loaded/disabled
state, safe owned-file reconciliation, symlink refusal, multi-project
coexistence, M7 migration ownership, unsupported-platform resolution, and
temporary-executable rejection. Existing maintenance/CLI tests retain the
systemd contract.

`make test-launchd` is an opt-in real-user-domain lifecycle test. It runs only
on macOS with `BEBOP_LAUNCHD_INTEGRATION=1` and an absolute stable
`BEBOP_LAUNCHD_BINARY`; it uses a temporary project and uninstalls its exact
project-scoped LaunchAgent. Linux CI/development does not claim launchctl
execution. Cross-builds include darwin amd64/arm64 compilation.

See [MAINTENANCE.md](MAINTENANCE.md), [ARCHITECTURE.md](ARCHITECTURE.md), and
[SAFETY.md](SAFETY.md) for operational details.
