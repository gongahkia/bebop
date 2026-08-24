# M5 — Deterministic Service Recipes

M5 adds a narrow authoring layer over the existing Compose service and M4
persistent-data models. Bebop can now turn a locally bundled, versioned,
reviewed recipe into ordinary service configuration and ordinary Compose source
without giving up deterministic planning, saved-plan checks, data ownership, or
secret containment.

## Delivered boundary

- A schema-versioned embedded corpus with deterministic listing, explicit
  non-`latest` image references, architecture metadata, health expectation,
  typed non-secret parameters, logical persistent resources, and required
  secret names.
- Controller-only `recipe list`, `show`, `validate`, `init`, and explicit
  `upgrade` commands, with clean JSON output and dry-run support for writes.
- Normal materialized `[services.NAME]` declarations, `compose.yaml` sources,
  M4 data declarations, and M3 secret-env references—not a recipe runtime.
- Generated provenance/self-fingerprints and drift-aware, local atomic upgrade
  publication. Manual source changes block recipe overwrite; deleting
  provenance intentionally hands ownership back to generic Compose.
- Planning/doctor architecture classification for intact recipe-managed
  services, plus nested-Docker coverage that proves materialized stateless
  deployment/no-op and stateful M4 backup/restore migration through the normal
  pipeline.

Recipes do not contact a target to initialize or upgrade. Target mutation stays
strictly behind the existing `inspect -> plan -> apply -> verify` path. The
embedded catalog has no network refresh, plugins, arbitrary templating, shell
hooks, or remote code execution.

## Compatibility and limits

Built-in recipe IDs and recipe versions are stable local compatibility keys.
Recipe/application/image versions are deliberately distinct. A known recipe
version stays usable for a later explicit compatible upgrade; version changes
that alter a service's logical persistent data or secret reference block rather
than attempting data migration. M4 remains the only persistent-state migration
mechanism.

M5 does not add an app marketplace, arbitrary user-defined recipes, background
update checks, image builds, automatic image upgrades, a secret manager,
database-specific backup behavior, or broad distro support. A recipe's
availability on `amd64`/`arm64` does not guarantee application-level data or
UID/GID portability across hosts.

## Validation

The unit corpus tests cover strict schema rejection, deterministic rendering and
fingerprints, typed parameter boundaries, YAML structure injection resistance,
secret non-leakage, provenance tampering, source drift/ejection, persistent
contract compatibility, and architecture classification. The opt-in nested
Docker tier materializes recipes then exercises the unchanged M3 Compose
lifecycle and M4 logical-volume backup/restore migration.
