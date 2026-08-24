# Backups, restore, and migration

M4 snapshots only persistent resources explicitly declared by a Compose service. It is a controller-side filesystem repository, not a daemon, cloud backend, scheduler, disk imager, encryption product, or Docker-data-root copy. A controller-mounted NAS or external disk may be used directly as `backup.destination`; M6 target storage resources do not redefine or manage that controller path.

M5 recipe materialization may generate the same explicit logical resource
declarations for a stateful service. A recipe does not widen this boundary:
only its generated `[[services.NAME.data]]` entries are eligible, and recipe
provenance, Compose releases, and controller secret inputs are still excluded.

```toml
[backup]
destination = ".bebop/backups"

[services.hello]
type = "compose"
source = "services/hello"

[[services.hello.data]]
name = "app-data"
type = "volume"
volume = "data" # Compose key, not source runtime name

[[services.hello.data]]
name = "uploads"
type = "path"
path = "/srv/hello/uploads"

[services.hello.backup]
consistency = "stop"
```

`volume` must be a declared, mounted Compose key. Bebop resolves the actual runtime name from the deterministic project and restores via the logical resource name, so source and destination volume names may differ. External volumes require the same explicit declaration but remain lifecycle-external. `path` must be a clean absolute target path below `/srv`, `/mnt`, or `/data`; system trees and the Bebop deployment root are rejected. Undeclared data is never backed up.

M6 path resources may instead use `storage = "NAME"` with a clean relative
`path`. Before backup or restore Bebop verifies the same declared filesystem
UUID/mount/read-write policy used by service convergence. A snapshot's logical
resource identity remains portable: destination storage names and runtime
volume names are never taken from source-host implementation details. Storage
placement changes require the normal backup/restore migration flow; Bebop does
not move live data. See [STORAGE.md](STORAGE.md).

`bebop doctor HOST` reports declared backup resources and the controller-side
repository path without creating it, pulling an image, or scanning data. A
missing destination is a warning because `backup create` creates it atomically;
a symlink or non-directory destination is a failure.

```sh
bebop backup create pi --service hello
bebop backup list
bebop backup show SNAPSHOT
bebop backup verify SNAPSHOT
bebop backup restore SNAPSHOT nuc --service hello --out restore.json
bebop backup restore --plan restore.json --yes
```

Without `--out`, restore renders its destination plan and asks for confirmation. A snapshot is immutable source data; a restore plan is a separate reviewed destination mutation.

Completed snapshots are staged then atomically published under `<destination>/snapshots/<id>/`, with `manifest.json` and `services/<service>/data/<resource>.tar`. The versioned manifest records source provenance, source identity/OS/architecture, logical resources, consistency, service configuration/deployment fingerprints, sizes, archive SHA-256 values, and its canonical digest. It stores no controller root, runtime volume name, or secret. Incomplete `.staging` data is never listed.

`backup verify` validates the manifest, expected repository shape, every archive digest, and archive safety. Full uncompressed tar data streams through bounded controller buffers. Only relative regular files, directories, and safe in-root symlinks survive; absolute/traversing paths, symlink escapes, hard links, devices, FIFOs, duplicate paths, and backslash paths are rejected.

`stop` is the default consistency policy. Under the normal target apply flock, Bebop stops a currently running service, streams declared data, restarts it, and verifies health. An already stopped service stays stopped; failed capture triggers best-effort recovery. `live` is explicit opt-in and cannot promise application-consistent data.

Restore is `empty-only`: missing volumes receive expected Compose labels, existing resources are inspected including hidden files, and a non-empty destination blocks before extraction. Bebop verifies snapshot/config/alias endpoint/host identity/restore-plan fingerprint/destination state, rebuilds the plan immediately before confirmation, and checks empty state again under the target lock. Changed state is stale and refused. M4 has no force, replace, or generalized rollback policy.

Migration is backup then restore: `hello/app-data` maps to a destination declaration with the same logical identity, followed by normal convergence. amd64/arm64 mismatch is a warning; numeric ownership and application format compatibility remain operator responsibilities.

The fixed `busybox:1.36.1` helper supports Linux amd64/arm64 and is unprivileged, socket-free, network-free, and mounted only to the declared resource (read-only for backup). It may pull once when absent and works offline when cached. M4 excludes Compose releases, `/var/lib/docker`, images, containers, Docker metadata, host roots/disks, controller secret env files, the M3 HMAC key, inventory credentials, and undeclared paths. Use encrypted storage beneath the destination when encryption at rest is required.
