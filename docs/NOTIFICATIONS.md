# Local-first notifications and operational events

M8 converts the safe structured outcome of a maintenance invocation into
versioned controller-local events. It is deliberately not a daemon, event
broker, cloud service, inbound API, command hook, or automatic-remediation
system. Bebop evaluates policy only after the underlying operation has written
its normal maintenance history record.

```text
maintenance result -> normalized event -> local issue state -> route -> sink
                                                   |                 |
                                             recovery/dedupe     delivery history
```

An operation remains authoritative. A snapshot that completed and verified is
valid even if every configured notification sink is unavailable. Notification
failure is shown separately in human/JSON maintenance output and never makes
the scheduler repeat the underlying backup merely to retry a webhook.

## Configuration

Notifications are optional. Existing configurations with no `[notifications]`
section have unchanged M7 behavior. The section is strict version-1 TOML and
does not participate in ordinary target config fingerprints or saved-plan
validity.

```toml
[notifications]
version = 1
enabled = true
notify_manual = false
state_dir = ".bebop/notifications"
history_max_entries = 1000

[[notifications.sinks]]
name = "events"
type = "file"
path = ".bebop/notifications/events.jsonl"

[[notifications.sinks]]
name = "ops"
type = "webhook"
url_env = "BEBOP_OPS_WEBHOOK_URL"
# optional; used only as the outbound Authorization header
authorization_env = "BEBOP_OPS_AUTHORIZATION"

[[notifications.routes]]
name = "operator"
sink = "ops"
events = ["backup.failed", "doctor.warning", "doctor.failed", "storage.failed", "service.unhealthy"]
severities = ["warning", "error", "recovery"]
recoveries = true
cooldown = "12h"
```

`state_dir` is controller-relative under the declaring configuration directory;
file sink paths must be below that state directory. They cannot be absolute or
escape with `..`; Bebop creates private real directories and rejects symlink/
group- or world-writable state roots. The default state directory is
`.bebop/notifications`; it is generated local state and ignored by Git.

Sinks name **where** to deliver; routes name **which** events to deliver. Sink
and route names are safe lowercase identifiers. Routes use exact stable event
names, optional severity filters, and an optional duration cooldown from Go's
duration grammar such as `12h` or `30m`. A route that selects a failure and has
`recoveries = true` also receives that failure's matching recovery; explicit
recovery event names are allowed only when recoveries are enabled. Severity
filters apply to active events; enabled recoveries follow their matched issue.

`notify_manual` defaults to false. Scheduled maintenance is evaluated when
notifications are enabled; manual `maintenance run` remains quiet unless this
option is explicitly enabled. No authoring, planning, apply, restore, recipe,
or storage-adoption command emits M8 notifications.

## Event model and taxonomy

Every serialized event has schema version, unique event ID, occurrence time,
type, severity, deterministic issue fingerprint, origin, logical target/job/
service/resource context, concise Bebop-controlled summary, and bounded
structured details. Event IDs distinguish occurrences; fingerprints identify
the same unresolved issue across runs. A fingerprint excludes timestamps, run
IDs, human messages, controller paths, machine IDs, volatile counters, and
secret values.

Implemented stable types are:

- `backup.succeeded`, `backup.failed`, `backup.retention_failed`
- `doctor.warning`, `doctor.failed`, `doctor.recovered`
- `updates.available`, `updates.cleared`
- `maintenance.failed`, `maintenance.skipped`, `maintenance.recovered`
- `storage.failed`, `storage.recovered`
- `service.unhealthy`, `service.recovered`

Severity is `info`, `warning`, `error`, or `recovery`. Success/info events are
silent unless explicitly routed. Doctor events derive from stable diagnostic
codes rather than diagnostic prose: storage and service findings receive their
specialized event families; other warnings/failures use the doctor family.
M8 intentionally receives Apt's safe summary counts rather than raw package
output, so `updates.available` is one stable availability issue rather than a
large or secret-prone package payload.

## Deduplication and recovery

Issue state is controller-local and atomically updated under an OS-backed local
lease. For each route:

```text
first active issue        -> deliver
same active issue         -> suppress
severity increase         -> deliver immediately
same issue after cooldown -> deliver reminder
healthy observation       -> remove active issue; deliver recovery only if
                              that route delivered the active issue
new failure after recovery -> deliver
```

With no cooldown, an active issue delivers once until recovery. Recovery is an
observed state transition, not a timer. A recovery with no remembered active
issue emits nothing. If failure delivery never succeeded, its route receives no
confusing recovery. A failed recovery delivery still removes the issue because
the infrastructure is objectively healthy again.

State is `state.json` plus per-delivery JSON records below
`state_dir/deliveries/`; writes use temporary files and atomic replacement.
History is bounded by `history_max_entries`. Corrupt state makes notification
evaluation fail safe without changing the maintenance operation or scanning old
M7 history. Repairing/removing notification state resets only dedupe/recovery
memory; it never affects target, plan, service, backup, or maintenance-history
correctness and does not retroactively notify historical failures.

Outbound delivery and local state cannot form a distributed transaction. The
state lease prevents concurrent duplicate decisions, but a controller crash
after a webhook accepts a POST and before local state is saved can cause a
later invocation to deliver that issue again. Receivers should treat the stable
event fingerprint as an idempotency/deduplication key when that distinction
matters.

## Sinks

### File

`type = "file"` appends self-contained, versioned JSON event envelopes to the
configured controller-local path. Append uses a local OS lease and `fsync`;
files are created mode `0600`. It is useful for local automation/audit and is
the recommended offline integration boundary. File paths must be relative and
cannot traverse or follow a symlinked parent into another location.

### Webhook

`type = "webhook"` sends one generic POST per selected event. It has no
provider-specific payload mode and can therefore bridge into a local service,
ntfy, Gotify, Home Assistant, n8n, or a custom receiver without adding a Bebop
integration.

```json
{
  "schema_version": 1,
  "event": {
    "schema_version": 1,
    "type": "backup.failed",
    "severity": "error",
    "target": "pi",
    "job": "nightly-backup",
    "summary": "Backup failed"
  }
}
```

The URL must come from `url_env`; Bebop never writes the resolved value to
state, history, CLI output, or errors. `authorization_env`, when declared,
becomes only the outbound `Authorization` header and is likewise never stored
or rendered. HTTPS with normal Go certificate verification is required, except
literal `localhost`, `127.0.0.1`, or `::1` HTTP endpoints for local testing/
self-hosting. Userinfo endpoints are rejected. Automatic redirects are not
followed, avoiding credential forwarding to a new host. The default transport
honors normal controller proxy environment variables.

Webhook delivery has a five-second total client timeout and at most three
attempts with deterministic 100ms/250ms backoff. It retries timeouts,
connection failures, and HTTP 429/502/503/504. It does not retry 401/403,
other invalid requests, TLS failures, redirects, malformed URLs, or missing
secret references. Response bodies are discarded; delivery history stores only
the safe category, attempt count, and HTTP status.

M8 intentionally does not implement a desktop sink: controller graphical
sessions are not a reliable notification boundary for unattended systemd user
timers or launchd LaunchAgents, and file/webhook sinks provide portable explicit
behavior. It also has no command sink and no inbound endpoint.

## Commands

```text
bebop notification list [--config bebop.toml] [--json]
bebop notification show SINK_OR_ROUTE [--config bebop.toml] [--json]
bebop notification status [--config bebop.toml] [--json]
bebop notification history [--config bebop.toml] [--json]
bebop notification test SINK [--config bebop.toml] [--timeout 15s] [--json]
```

`status` is controller-only: it reports configuration, secret-reference
availability, and active issues without probing targets or POSTing a webhook.
`test` emits a clearly marked synthetic event directly to exactly one sink. It
does not contact a target, write maintenance history, or alter active issue
state.

## Secret boundary

Event derivation accepts only safe maintenance result fields. It does not
serialize raw stderr, command output, secret env content, HMAC keys, webhook
URLs, authorization headers, SSH command lines, controller absolute paths, or
machine IDs. This applies before JSON serialization, local state/history, file
sinks, and webhook payloads. Delivery errors use categories such as `timeout`,
`server_error`, or `authentication`, never raw endpoint strings or response
bodies.

M9 scheduler artifacts remain outside this boundary: neither systemd units nor
launchd plists contain webhook values or authorization headers. On macOS, a
LaunchAgent does not receive an interactive shell environment by default; an
operator must arrange referenced variables in the launchd user domain. `bebop
notification status` can report availability to the current controller process,
but it cannot prove that a later LaunchAgent receives the same environment.
