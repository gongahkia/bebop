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
minimum_capacity_bytes = 100000000000 # optional
minimum_free_bytes = 10000000000       # optional
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

## Inspection and management

`bebop storage inspect HOST` renders normalized `lsblk --json` and
`findmnt --json` facts. `storage list`, `storage show NAME`, and `storage
doctor` render declared resource assessment. `storage adopt NAME HOST --mount
PATH --filesystem-uuid UUID` confirms an existing ready mount and atomically
appends only local config metadata; adoption has no target-side mutation.

An assessment distinguishes ready, missing, root-spill (the desired directory
is really served by `/`), wrong UUID, wrong filesystem type, read-only,
capacity/free-space threshold failure, and unavailable topology. Deploy,
backup, and restore refuse a storage-relative path unless it is ready.

With `managed_mount = true`, a normal reviewed plan can create an empty,
non-symlink mount directory; append a marker-scoped UUID fstab entry after
`findmnt --verify`; and mount it. Any existing fstab entry for that mount point,
non-empty mount point, wrong filesystem, or failed verification blocks. Bebop
does not rewrite user fstab lines. The ordered actions are mount-point,
mount-config, mount, then dependent service actions, all under the ordinary
target apply lock.

Storage topology and filesystem identity are relevant saved-plan state. Exact
free space is intentionally not fingerprinted; policy threshold satisfaction
and mount UUID/type/read-only state are. A changed device pathname that still
provides the declared UUID does not invalidate a plan.

Changing placement for existing application state is not data migration. Take
a verified backup, restore into the new declared placement, then converge the
service. M6 never moves live bind-path data automatically.
