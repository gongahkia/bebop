# Roadmap

## Implemented in M5: deterministic service recipes

- Small embedded, schema-validated, offline corpus of reviewable Compose recipe
  versions with pinned image metadata, architecture coverage, typed parameters,
  logical persistent-resource declarations, and secret references.
- Controller-only materialization into ordinary service config/source plus
  generated provenance and compatible explicit upgrades; the existing M3/M4
  runtime, saved-plan, backup, and restore paths remain authoritative.
- Strict rendering/provenance drift boundaries and disposable Compose coverage
  for materialized stateless convergence and stateful portable data migration.

## Implemented in M4: backup, restore, and host migration

- Explicit logical Compose volume and safe absolute bind-path data declarations,
  controller-local full snapshots, streamed tar sanitization, canonical manifest
  integrity, completion staging, inspection, and corruption refusal.
- Stop-consistent backup with target locking and original runtime-state recovery,
  plus separate destination restore plans with identity/config/state/snapshot
  protections and empty-only restore semantics.
- Portable logical resource mapping across distinct Docker project volume names,
  with disposable two-target exact-data migration integration coverage.

## Implemented in M3: deterministic service runtime

- Generic strict Compose service resources with deterministic source manifests,
  staged deployment activation, project-scoped lifecycle states, Docker Compose
  capability planning, and bounded health-aware verification.
- Source/runtime/deployment drift correction, service input saved-plan guards,
  target deployment metadata, status/doctor service visibility, and a narrow
  HMAC-based secret environment reference boundary.
- Opt-in nested-Docker Compose integration coverage for deploy/update/drift/
  stop/volume-preserving removal, alongside M2's real SSH tier.

## Implemented in M2: remote control plane and portable plans

- Versioned, strict, atomically written `bebop.hosts.toml` inventory with
  aliases, host-local desired-config references, host management commands, and
  literal-target compatibility.
- Read-only `bootstrap`/doctor preflight with OpenSSH failure classification,
  OS/architecture/apt/systemd/privilege readiness, and machine identity facts.
- Canonical, versioned saved-plan artifacts with config and relevant-state
  fingerprints, target identity protection, tamper detection, and regeneration
  before execution.
- Target-side apply flock, selected module-level preconditions, and bounded,
  deterministic `status --all` / `doctor --all` read workflows.
- Opt-in disposable Docker coverage for real SSH transport against Debian and
  Ubuntu, alongside deterministic unit/high-fidelity safety tests.

## Implemented in M0/M1

- Deterministic local/OpenSSH transport, normalized Debian-family facts, strict
  TOML, immutable structured plans, apply verification, and no-op tests.
- Debian, Ubuntu, and Raspberry Pi OS target recognition.
- Base filesystem, automatic updates, Docker, Tailscale package/service, and
  conservative SSH hardening.
- Read-only diagnostics/status, JSON, CI, and opt-in disposable Debian inspect.

## Deliberately later

- Fedora and Arch targets; macOS targets through a Linux VM; Windows targets
  through WSL2/VM.
- Passive LAN discovery and a TUI.
- M6: explicit storage workflows and placement policy.
- M7: broader Linux distribution support; M8: macOS/Windows target adapters.
- Broad application catalog, automated recipe update discovery, notifications,
  and richer drift controls.
- Scheduled/external backup repositories with the same manifest and restore
  safety model; no storage provisioning or implicit disk automation.
- Signed plans, generalized rollback, and transactions.
- Deterministic agent/MCP integration surfaces that call Bebop APIs, never an
  LLM inside Bebop.
