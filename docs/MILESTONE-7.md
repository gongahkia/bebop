# M7 — Scheduled Operations & Unattended Maintenance

M7 makes a small home-server control plane useful over time without making
Bebop a daemonized infrastructure platform. The controller can declare typed
scheduled backup, doctor, and update-awareness jobs, install deterministic
Linux systemd user timers explicitly, and inspect their local history/state.
Targets remain agentless.

## Delivered boundary

- Strict versioned controller maintenance policy, portable daily/weekly/hourly
  schedule grammar, optional controller-local maintenance windows, enablement,
  deterministic job fingerprints, and explicit manual window override.
- A common maintenance runner with controller local per-job leases, predictable
  `success`/`warning`/`failure`/`skipped` records, bounded atomic structured
  history, and no raw terminal output or secret values in history.
- Linux systemd-user service/timer materialization using absolute captured
  executable/project/config/inventory paths, direct quoted exec arguments,
  `Persistent=true`, explicit install/uninstall, idempotence, and stale/tamper
  detection from deterministic unit content.
- Reuse of M4 backup creation and M6 storage guards for scheduled backups,
  with per-job snapshot provenance and deterministic `keep_last` retention
  only after a verified successful new snapshot. Manual and other-job snapshots
  are preserved.
- Reuse of normal read-only doctor/preflight and a Debian apt simulation update
  check. Optional metadata refresh is `apt-get update` under target locking;
  no upgrade/install/reboot path exists.

## Explicit limits

M7 has no controller daemon, cloud scheduler, target scheduler, scheduler
adapter for macOS/Windows, arbitrary command jobs, scheduled restore/apply,
automatic service/recipe/image/package upgrades, notifications, retries, or
fleet backup orchestration. A systemd user manager must be available for Linux
timer installation. Scheduled SSH still needs normal non-interactive key/host
key authentication and remote non-interactive sudo where the underlying
operation needs it.

## Validation boundary

Unit coverage proves strict policy parsing, schedule/window boundaries,
deterministic and shell-free unit generation, stale/tampered unit detection,
idempotent owned-unit reconciliation, local lock behavior, bounded history,
secret-safe records, retention scope/order/corruption behavior, and apt update
simulation parsing. The opt-in Docker-in-Docker maintenance tier proves real
Compose backup runtime recovery plus maintenance-provenance retention that
keeps manual snapshots. It does not claim execution by a real systemd user
manager; adapter install/status behavior is isolated through a disposable
controller filesystem and fake systemd command runner.
