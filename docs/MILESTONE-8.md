# M8 — Local-first notifications and operational events

M8 closes Bebop's unattended operational loop without turning it into an
always-on management service. Scheduled maintenance still performs the same
M4/M6/M7 backup, doctor, and update-awareness operations. After immutable
maintenance history is written, M8 derives normalized safe events, evaluates
local dedupe/recovery state, and makes bounded outbound delivery attempts.

## Delivered boundary

- Strict versioned `[notifications]` policy with named file/webhook sinks and
  named routes, exact stable event filters, optional severity filters,
  recoveries, cooldown reminders, and environment-only webhook secrets.
- Versioned normalized events with distinct unique event IDs and deterministic
  issue fingerprints. Maintenance maps backup, retention, doctor/storage/
  service findings, Apt update awareness, failures, skips, and healthy state
  transitions into the M8 taxonomy.
- Private controller-local atomic state and bounded per-delivery history. First
  failures notify; repeats suppress; severity escalation and cooldown reminders
  notify; observed recovery clears state and can notify only previously
  successful routes.
- Structured local JSONL file delivery and generic HTTPS webhook delivery with
  normal TLS verification, no redirects, secret URL/header indirection,
  five-second timeout, and limited transient retry classification.
- Notification results remain separate from operation results. A broken sink
  cannot invalidate a verified snapshot or change the maintenance exit result.
- A shared OS-backed controller lease: `flock` on Unix and `LockFileEx` on
  Windows. Kernel ownership releases after process death, so a stale lock path
  alone cannot permanently block a maintenance job.

## Explicit limits

M8 has no daemon, cloud relay, telemetry, notification queue, remote command,
inbound webhook/API, chatops, automatic remediation, arbitrary command hook,
desktop adapter, vendor integration catalog, escalation engine, or historical
event replay. It does not make Windows systemd scheduling available; Windows
keeps the existing cross-build/manual controller boundary with a real local
lease implementation.

## Validation boundary

Unit coverage verifies strict policy parsing, stable/secret-safe event
fingerprints, routing, dedupe, severity escalation, cooldown boundaries,
restart persistence, corrupt-state failure behavior, file-sink symlink
rejection, webhook retry/TLS/redirect/401 handling, operation/delivery
separation, and abrupt lock-holder death/reacquisition. The opt-in-free local
notification integration tier uses only `httptest` and temporary project roots:
it proves first delivery, duplicate suppression, restart persistence, recovery,
file output, secret absence, and a successful maintenance backup outcome whose
webhook delivery repeatedly fails. It never contacts an external endpoint.

See [NOTIFICATIONS.md](NOTIFICATIONS.md), [MAINTENANCE.md](MAINTENANCE.md),
[ARCHITECTURE.md](ARCHITECTURE.md), and [SAFETY.md](SAFETY.md).
