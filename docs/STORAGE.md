# Storage workflows and placement policy

M6 adds explicit storage placement for persistent **bind-path** resources. It
does not provision storage: Bebop never partitions, formats, resizes, encrypts,
unmounts, selects a disk, moves Docker's data root, or touches `/var/lib/docker`.
The target administrator prepares a filesystem first; Bebop recognizes it by
filesystem UUID and may mount that existing filesystem only with explicit
`managed_mount = true` authorization.

```toml
[storage.resources.bulk]
mount = "/mnt/bulk"
filesystem_uuid = "11111111-2222-3333-4444-555555555555"
filesystem_type = "ext4"             # optional
minimum_capacity = "100GiB"            # optional binary threshold
minimum_free = "10GiB"                 # optional binary threshold
managed_mount = false                  # default

[[services.hello.data]]
name = "media"
type = "path"
storage = "bulk"
path = "media"
```

`storage` plus a relative `path` resolves to `/mnt/bulk/media`. The matching
Compose bind source can use `${BEBOP_STORAGE_BULK}/media`, so the absolute
mount prefix is declared once. Bebop injects only these fixed, generated
storage variables into Compose; arbitrary Compose bind interpolation remains
rejected. Named Docker volumes remain supported but are intentionally not
placeable in M6: Docker's data root is out of scope.

Before deployment or restore creates a storage-relative bind directory, Bebop
checks that the declared mount and every already-existing component below it is
a real directory rather than a symlink. This prevents an existing nested path
from redirecting Bebop-owned data outside the declared filesystem.

## Inspection and management

`bebop storage inspect HOST` renders normalized `lsblk --json` and
`findmnt --json` facts. `storage list`, `storage show NAME`, and `storage
doctor` render declared resource assessment. `storage adopt NAME HOST --mount
PATH` confirms an existing ready mount, records its observed UUID/type, and
atomically appends only local config metadata; `--filesystem-uuid` may assert
an expected identity. Adoption has no target-side mutation.

An assessment distinguishes ready, missing, root-spill (the desired directory
is really served by `/`), wrong UUID, wrong filesystem type, read-only,
capacity/free-space threshold failure, unsupported filesystem, fstab conflict,
and unavailable topology. M6 supports persistent-data placement only on local
`ext2`, `ext3`, `ext4`, `xfs`, and `btrfs` filesystems with an observed
filesystem UUID. Other filesystems remain inspectable but are blocked for
placement; mounted network filesystems are not a M6 placement target. An
already-unlocked encrypted device may be used only when its mounted supported
filesystem is normally visible with a UUID; Bebop never unlocks or manages
encryption. M6 has no filesystem-specific mutation behavior. Deploy,
backup, and restore refuse a storage-relative path unless it is ready.

With `managed_mount = true`, a normal reviewed plan can create an empty,
non-symlink mount directory; append a marker-scoped UUID fstab entry after
`findmnt --verify`; and mount it. An equivalent existing UUID/mount mapping is
accepted as externally managed and is never rewritten. A conflicting mapping
for either the mount point or UUID, a non-empty mount point, wrong filesystem,
or failed verification blocks; `bebop storage doctor` names the fstab conflict.
The ordered actions are mount-point, mount-config, mount, then dependent
service actions, all under the ordinary target apply lock.

Storage topology and filesystem identity are relevant saved-plan state. Exact
free space is intentionally not fingerprinted; policy threshold satisfaction
and mount UUID/type/read-only state are. A changed device pathname that still
provides the declared UUID does not invalidate a plan. Capacity accepts binary
`KiB`, `MiB`, `GiB`, `TiB` and decimal `KB`, `MB`, `GB`, `TB`; bare values are
rejected. `*_bytes` remains available for generated tooling. Restore reserves
the snapshot's logical archive size plus five percent (at least 64 MiB) as a
preflight safety estimate, then checks again under the target lock; free space
is not a quota and can still race external writers.

Changing placement for existing application state is not data migration. Each
managed release records a non-secret placement fingerprint. A subsequent
storage-backed placement change is blocked before deployment/start; take a
verified backup, restore into the new declared placement, then converge the
service. M6 never moves live bind-path data automatically.
