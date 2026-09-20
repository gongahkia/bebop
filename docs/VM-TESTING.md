# VM smoke harness

`make test-vm-smoke` is an explicit real-host smoke tier. It uses
`tools/vmtest`, direct QEMU, a disposable qcow2 overlay, cloud-init NoCloud
seed data, an ephemeral SSH key, and Bebop's normal OpenSSH transport. It never
uses a test-only Bebop transport, personal SSH configuration, bridged LAN
networking, or a writable cached base image.

The checked-in [image manifest](../testdata/vm/images.json) pins the official
Debian 13, Fedora 44, and Arch amd64 cloud artifacts currently prepared by the
harness. The tool verifies a pinned SHA-256 or SHA-512 value before putting a
base image in `.bebop/vm/images/`, marks that cache entry read-only, and builds
each run from a temporary qcow2 overlay. Fedora's pinned value is taken from
its signed upstream checksum file; signature/keyring review remains a
maintainer responsibility when updating the manifest.

Prerequisites are intentionally strict: `qemu-system-x86_64`, `qemu-img`,
`cloud-localds`, OpenSSH, `ssh-keygen`, Go, and `/dev/kvm`. The default rejects
software emulation. `-allow-tcg` is an explicit slower fallback only. Missing
tools, missing KVM, checksum mismatch, provisioning failure, boot timeout, or
SSH failure fail the selected run; none are silently represented as a passing
VM test.

The smoke tier boots a real PID 1, waits for SSH using a run-private known-host
file, and runs `bebop inspect`, `bebop doctor`, and `bebop status` over normal
SSH. QEMU user networking exposes only an ephemeral loopback SSH forward.
Console output is retained in the temporary run directory only while a failed
run is being reported; keys, seed data, overlays, and logs are removed at
cleanup.

This repository does **not** yet have reviewed, bootable, provisioned VM paths
for Alpine/OpenRC, Void/runit, Devuan/SysVinit, or Artix/dinit. It also does
not yet implement Tier 2+ VM mutations, reboot persistence, storage,
backup/restore, SSH-hardening, saved-plan, or failure-injection VM tests.
Existing container and fake-transport coverage remains the evidence for those
paths. Do not describe Bebop as having complete real-host VM proof until those
paths are added and run.

When adding a platform, pin an immutable official artifact and checksum in the
manifest, review its source checksum/signature procedure, implement only the
necessary official provisioning path, then add its tier coverage. Never replace
an unavailable VM with a container and call it equivalent.
