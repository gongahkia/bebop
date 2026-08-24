# M6 — Storage workflows and placement policy

M6 makes persistent bind-path placement explicit without turning Bebop into a
disk manager. A storage resource identifies an already-formatted target
filesystem by UUID, expected mount point, optional type and capacity policy.
Normalized JSON `lsblk`/`findmnt` facts feed the existing planner and saved
plan state. The storage module may mount only an explicitly authorized existing
filesystem through a marker-scoped fstab entry; it never formats, partitions,
selects a disk, changes Docker storage, or migrates live data.

Service data may declare a logical storage resource and relative target path.
Compose sources use a fixed generated `${BEBOP_STORAGE_NAME}` interpolation,
so physical mount prefixes stay in the storage declaration. Service deploy/start
plans gain stable mount dependencies and immediate identity preconditions.
Backup and restore use the same placement guard and therefore refuse root spill,
wrong UUID, read-only, and threshold-failing locations before data mutation.
Restore checks the snapshot archive size again immediately before extraction.

The new controller-side commands are `storage list`, `show`, `inspect`,
`doctor`, and read-only `adopt`. Storage inspection is available in normal
facts/status and doctor reports readiness. The next coherent milestone should
focus on scheduled/external backup repositories, not storage provisioning or
application catalog expansion.

The opt-in `make test-storage-integration` tier uses a temporary ext4 image
inside privileged disposable Docker-in-Docker. It verifies Bebop's scoped fstab
write, UUID mount, post-mount verification, and no-op second plan without
touching any controller disk or `/etc/fstab`.
