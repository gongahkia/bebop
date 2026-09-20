# Local release verification

Release publication and CI automation are intentionally not part of this
repository workflow. A maintainer can build release-shaped artifacts locally:

```sh
make release-dry-run VERSION=v0.2.0
```

The command requires a clean worktree, runs `make check`, verifies that a
native controller binary reports the requested exact tag, and writes
`dist/v0.2.0/`. It produces SHA-256 checksums for these controller targets:

- linux amd64 and arm64;
- darwin amd64 and arm64;
- windows amd64 and arm64.

Windows is a supported cross-build controller target; controller-native
scheduling remains explicitly unavailable there. The generated archives contain
the binary and README only because the repository currently has no separate
license file. The dry run never creates a tag, publishes an asset, or contacts
a release service. `dist/` is ignored by Git.

Before a public release, run `go test -race ./...`, `govulncheck ./...`, the
available integration tiers, and the reviewed VM suite. Checksums provide
integrity metadata; no signing or hosted provenance workflow is configured in
this repository.
