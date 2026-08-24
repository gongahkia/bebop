# M4 — Backup, Restore & Host Migration

M4 makes declared Compose persistent state portable without turning Bebop into a
general-purpose backup service. A server is now reproducible configuration plus
replaceable deployment state plus a verifiable snapshot of explicitly declared
persistent data.

## Scope

M4 supports controller-side full snapshots of explicitly declared Docker named
volumes and safe absolute bind paths. The repository is an ordinary local or
mounted controller filesystem. It has no daemon, schedule, object-storage
backend, deduplication, filesystem snapshotting, disk imaging, encryption, or
application-specific database adapter.

Only `[[services.NAME.data]]` resources are included. Compose use of a volume
does not authorize backup by itself. Deployment releases, Docker daemon state,
controller service sources, and `secret_env_file` inputs remain outside the
snapshot boundary.

## Backup artifact

Each completed snapshot resides below `snapshots/<timestamp-random-id>/` and
contains `manifest.json` plus one tar archive per logical resource. The manifest
is schema-versioned and records source provenance, service configuration and
deployment digests, logical resource identity/type, archive location, sizes,
per-archive SHA-256, consistency mode, and a canonical manifest digest. It does
not rely on source hostname, IP, controller path, or source runtime Docker volume
name to restore data.

Creation writes only into `.staging/`, verifies every stored archive and the
manifest, and atomically publishes a completed snapshot. Incomplete staging
data is not listed or restorable. `bebop backup verify` checks manifest and
resource digests, expected repository shape, and safe archive contents.

## Consistency and locking

`stop` is the default consistency policy. Bebop records runtime state, acquires
the existing target apply flock, stops a currently running service, streams its
declared data to the controller, then returns the service to its original state
and uses normal Compose health verification. If capture fails after a stop it
makes the same best effort to recover runtime state and reports recovery failure
alongside the backup failure.

`live` is explicit opt-in. It does not stop the service and can be useful for
data that tolerates a live filesystem snapshot, but Bebop makes no application
consistency claim for it.

## Restore and migration

A snapshot is immutable source data, not a command to execute. Restore builds a
separate schema-versioned self-hashed plan. The plan binds the snapshot manifest
digest to the destination machine identity, normalized configuration digest,
logical service/resource mapping, and a relevant destination-state fingerprint.
Saved restore plans are revalidated after fresh inspection; changed destination
state, config, snapshot, or host identity is rejected before mutation.

M4 uses `empty-only` restore semantics. It creates a missing declared ordinary
volume or bind directory, but blocks any non-empty destination resource rather
than overwriting it. Extraction is rooted in exactly that declared resource and
uses a narrow, unprivileged helper. After extraction Bebop invokes the existing
service planner/apply path, so deployment source and lifecycle stay owned by M3.

Migration is therefore a normal sequence:

```text
backup source host -> verify snapshot -> restore to destination -> normal apply
```

Logical resource names bridge host-specific Compose runtime volume names. An
amd64/arm64 difference is visible as a warning, because volume data may be
portable but an application image or ownership expectation can still differ.

## Verification

The disposable nested-Docker integration tier proves a running source service
with known named-volume content can be backed up, verified, restored to a
second target whose runtime volume name differs, converged, and read back with
exact original bytes. Unit tests cover strict configuration, archive traversal
and link rejection, partial staging exclusion, canonical manifests, corruption
refusal, restore plan integrity/state guards, and bounded stream reads.

See [BACKUPS.md](BACKUPS.md) for the operator contract and
[ARCHITECTURE.md](ARCHITECTURE.md) and [SAFETY.md](SAFETY.md) for implementation
and security boundaries.
