# Roadmap

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
- LAN discovery, multi-host inventory, remote bootstrap, and a TUI.
- Docker Compose application catalog, backups, migration, and notifications.
- Explicit storage workflows with no implicit disk automation.
- Signed/saved plans, richer drift controls, and rollback/transactions.
- Deterministic agent/MCP integration surfaces that call Bebop APIs, never an
  LLM inside Bebop.
