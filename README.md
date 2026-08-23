# Bebop

Bebop is a deterministic home-server converger for machines you already own.
It inspects a Debian-family target, compares it with a small declarative
`bebop.toml`, presents an ordered plan, applies only the reviewed changes, then
re-inspects to prove convergence. It is a CLI, not a dashboard, app store, or
bespoke operating system.

M0/M1 supports Debian 12/13, Ubuntu 22.04/24.04, and Raspberry Pi OS based on
Debian 12/13 as targets. The controller builds for Linux and macOS; macOS and
Windows targets are deliberately unsupported.

## Quick start

```sh
make build

# Read-only discovery through your existing OpenSSH configuration.
./bin/bebop inspect --target ssh://pi@raspberrypi.local

# Writes local config only; it does not modify the target.
./bin/bebop init --target ssh://pi@raspberrypi.local --output bebop.toml

# Review semantic changes, or exact static scripts.
./bin/bebop plan --target ssh://pi@raspberrypi.local --config bebop.toml
./bin/bebop plan --target ssh://pi@raspberrypi.local --config bebop.toml --show-commands

# Requests confirmation unless --yes is supplied.
./bin/bebop apply --target ssh://pi@raspberrypi.local --config bebop.toml

./bin/bebop status --target ssh://pi@raspberrypi.local
./bin/bebop plan --target ssh://pi@raspberrypi.local --config bebop.toml
# No changes.
```

`inspect`, `plan`, `status`, and `doctor` have `--json`. `apply --json --yes`
returns both its reviewed plan and result in one JSON document. Target syntax is
`local` or `ssh://user@host[:port]`. Bebop uses the installed OpenSSH client,
honours normal `~/.ssh/config` and host-key checking, and uses BatchMode so it
never receives an SSH password.

## Current desired state

The generated configuration is intentionally small:

```toml
version = 1

[server]
name = "home"

[features]
automatic_updates = true
ssh_hardening = true
docker = true
tailscale = true

[network]
firewall = "disabled"

[storage]
data_root = "/srv/bebop"
```

It can create and permission the configured data root, enable Debian's
`unattended-upgrades`, install `docker.io` and start `docker.service`, install
Tailscale from an explicit official repository mapping, and add a conservative
SSH drop-in. Tailscale authentication remains manual: after installation run
`sudo tailscale up` on the target.

`network.firewall` accepts only `"disabled"` in this milestone. Bebop reports
UFW/nftables/firewalld state but never changes firewall rules.

## Safety and limits

Planning does not mutate a target. Privileged changes require a root SSH user
or non-interactive `sudo`; Bebop neither prompts for nor stores passwords. It
rebuilds the plan immediately before confirmation, executes only structured
planned actions, verifies each, then re-inspects and re-plans.

SSH hardening is fail-closed: the connected user must have an authorized key,
the existing config must validate, and the Debian drop-in include must exist.
Bebop validates a temporary candidate before replacing only its own drop-in.

M0/M1 does not partition, format, resize, mount, or erase disks; expose public
services; alter routers, DNS, or firewall rules; rewrite Docker projects;
install an OS; collect telemetry; or use AI/LLM APIs. See
[docs/SAFETY.md](docs/SAFETY.md) for the exact boundary.

## Development

```sh
make format
make check
make test-race
make build
make cross
```

`make test-integration` is opt-in and needs a running Docker daemon. It runs
only `bebop inspect --json` in a disposable `debian:12` container and never
runs `apply` or modifies the development host.

Read [the architecture](docs/ARCHITECTURE.md), [safety policy](docs/SAFETY.md),
[M0/M1 scope](docs/MILESTONE-0.md), and [roadmap](docs/ROADMAP.md) before
extending Bebop.
