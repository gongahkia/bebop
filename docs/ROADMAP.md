# Roadmap

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
- M3: a generic deterministic service/Compose-project primitive, without an
  application catalog.
- M4: backups and state migration; M5: explicit storage workflows; M6: broader
  Linux distribution support; M7: macOS/Windows target adapters.
- Docker Compose application catalog, notifications, and richer drift controls.
- Explicit storage workflows with no implicit disk automation.
- Signed plans, generalized rollback, and transactions.
- Deterministic agent/MCP integration surfaces that call Bebop APIs, never an
  LLM inside Bebop.
