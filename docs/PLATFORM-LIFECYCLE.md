# Platform lifecycle

`internal/facts/platform.go` is the compile-time authority for reviewed target
support. A distro family is not support for a new release, architecture, libc,
or init combination by implication.

## Review a new fixed release

1. Confirm upstream support and obtain an official image or rootfs artifact.
2. Record exact `os-release`, architecture, libc where relevant, and active
   init facts in fixtures.
3. Review package-manager tools, signing/provenance, repository policy,
   package holds, and safe update-check behavior.
4. Verify the actual Docker, Compose V2, Tailscale, OpenSSH, and service
   integration contracts for every proposed architecture.
5. Verify automatic-update policy, storage/lock prerequisites, mutable-root
   behavior, and SELinux/LSM implications where applicable.
6. Add the exact policy entry and explicit capability states; do not use
   `ID_LIKE` or a generic family fallback.
7. Add OS, package, init, saved-plan, doctor, and capability-parity coverage.
8. Run focused tests, container metadata checks, and the applicable
   representative VM tiers before documenting the support claim.
9. Update [SUPPORT.md](SUPPORT.md), release notes, and retire an older release
   only in a separate deliberate review after upstream support ends.

## Rolling platforms

Arch, openSUSE Tumbleweed, Void, and Artix use rolling identity rather than a
snapshot gate. Their image snapshots and repository metadata are nevertheless
review inputs. Periodically verify package names, service definitions,
repository policy, Docker/Tailscale availability, signature behavior, and
update semantics. Drift must open a maintainer review; it must not
automatically rewrite the matrix or package mappings.

## External dependency checks

When the VM harness is available, its manifest pins reviewed official image
artifacts and checksums. Re-run its manifest/image verification and the
existing package-metadata integrations on a scheduled maintainer cadence.
Failures are evidence for review, not permission to accept a new image,
repository, package, or key automatically.
