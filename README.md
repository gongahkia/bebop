# Bebop

Bebop is a deterministic, agentless home-server control plane for machines you
already own. It keeps a local inventory, inspects Debian-family targets through
your existing OpenSSH setup, compares each with a small declarative
`bebop.toml`, presents an ordered plan, and applies only reviewed changes. It
is a CLI, not a dashboard, app store, cloud service, or bespoke operating
system.

M0/M3 supports Debian 12/13, Ubuntu 22.04/24.04, and Raspberry Pi OS based on
Debian 12/13 as targets. The controller cross-builds for Linux, macOS, and
Windows remote-SSH workflows; macOS and Windows targets are deliberately
unsupported.

## Quick start

```sh
make build

# Register controller-side metadata only; no target is contacted.
./bin/bebop host add pi \
  --target ssh://pi@raspberrypi.local \
  --config hosts/pi.toml
./bin/bebop host list

# Read-only readiness assessment through your existing OpenSSH configuration.
./bin/bebop bootstrap pi
./bin/bebop inspect pi

# Writes local config only; it does not modify the target.
./bin/bebop init pi --output hosts/pi.toml

# Review a deterministic plan and retain a portable review artifact.
./bin/bebop plan pi --out .bebop/plans/pi.plan.json
./bin/bebop plan pi --show-commands

# Reconnect, validate the saved plan is still safe, then request confirmation.
./bin/bebop apply --plan .bebop/plans/pi.plan.json

./bin/bebop status --all
./bin/bebop doctor --all
./bin/bebop plan pi
# No changes.
```

Inventory aliases are additive: the original literal target workflow remains
available, for example `bebop plan --target ssh://pi@raspberrypi.local --config
bebop.toml`. `inspect`, `plan`, `status`, `doctor`, `bootstrap`, and host list/
show have JSON output where useful. `apply --json --yes` returns both its
reviewed plan and result in one JSON document. Target syntax is `local` or
`ssh://user@host[:port]`. Bebop uses the installed OpenSSH client, honours
normal `~/.ssh/config`, agents, ProxyJump, IdentityFile, and host-key checking,
and uses BatchMode so it never receives an SSH password.

## Inventory and saved plans

The default inventory is `bebop.hosts.toml` in the controller working
directory. It is strict, versioned TOML and contains only public controller
metadata:

```toml
version = 1

[hosts.pi]
target = "ssh://pi@raspberrypi.local"
config = "hosts/pi.toml"
```

Aliases are 1–63 safe identifier characters. Host config paths are relative to
the inventory directory and cannot escape it with `..`; an explicit `--config`
overrides an inventory association. Inventory writes are sorted and atomic.
`host remove NAME --yes` removes only this local metadata and never contacts a
target. The inventory is suitable for Git, but passwords, private keys, SSH
tokens, and Tailscale keys must never be placed in it.

`plan --out FILE` writes a versioned JSON artifact with its desired-config
fingerprint, relevant observed-state fingerprint, target endpoint, machine
identity, complete ordered plan, and SHA-256 self-fingerprint. It contains no
timestamps, maps, or secrets. `apply --plan FILE` validates the schema and
self-fingerprint, verifies the recorded local config has not changed, then
re-inspects. It refuses changed relevant convergence state, a changed machine
ID (or hostname/OS fallback when no machine ID exists), or a changed current
inventory target for the recorded alias. It regenerates the plan and executes
that output instead of treating JSON scripts as authority. Memory, kernel, and
filesystem-free-space changes do not stale a plan because no module uses them.

Plan files can be committed wherever a review workflow needs them; `.bebop/`
is reserved for local generated state but plans are not ignored by default. M3
also records a deterministic service-input fingerprint made from each
non-secret source manifest and keyed secret marker. Editing a Compose source or
referenced secret after review makes `apply --plan` refuse before target
mutation.

## Compose workloads

M3 adds one generic, built-in Compose service resource. It is not an
application catalog: you provide the source directory and Compose file.

```toml
[services.hello]
type = "compose"
source = "services/hello"
state = "running"
health_timeout = "2m"
```

`source` is resolved relative to the declaring `bebop.toml`, never the
controller's current directory. It must contain exactly one root-level
`compose.yaml`, `compose.yml`, `docker-compose.yaml`, or
`docker-compose.yml`. Bebop rejects source traversal, symlinks, special files,
ambiguous Compose files, `.git`, `node_modules`, Compose `build`, profiles,
`extends`, YAML aliases, and duplicate fixed host-port declarations before a
target is contacted. Compose uses an explicit image; Bebop does not build
images or pull them except when `docker compose up` itself needs a missing
image.

```sh
mkdir -p services/hello
# add services/hello/compose.yaml
./bin/bebop plan pi --config bebop.toml --out .bebop/plans/pi.plan.json
./bin/bebop apply --plan .bebop/plans/pi.plan.json
./bin/bebop status pi
```

`running` stages the deployment and reconciles its Compose project. `stopped`
keeps the deployment and stops its containers. `absent` runs `docker compose
down --remove-orphans` without `-v`, removes only Bebop's active deployment
link, and retains named volumes, bind-mounted data, and retained release trees.
Each project name is deterministic and unique per `server.name` plus service
name, so an update to one declared service cannot target another project's
containers.

Deployment releases are replaceable content. Relative bind mounts such as
`./data:/data` are rejected because they could place persistent data inside a
release that a later deployment update replaces. Use named volumes or deliberate
absolute target paths for persistent data; `absent` never removes those volumes
or paths.

Services need Docker Engine and Docker Compose v2. Bebop detects Compose; when
the target apt repositories advertise `docker-compose-plugin` or
`docker-compose-v2`, its existing Docker module can install it through a
reviewed plan. Every Compose invocation receives an empty environment and
`--context default`; controller `DOCKER_HOST` and `DOCKER_CONTEXT` are not
used.

For a small secret boundary, set `secret_env_file` to a controller-local file
relative to the config and reference `.bebop-secret.env` from the Compose
file's `env_file`. Bebop transfers that file with mode `0600`, never renders its
contents, and tracks it with an HMAC keyed by a local
`.bebop/cache/secret-hmac.key`. Secret rotation requires a new saved plan;
controllers without that local key safely require re-planning. Never put secret
values in TOML, inventory, service source files intended for review, plans, or
logs. See [service documentation](docs/SERVICES.md).

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

Planning, bootstrap, doctor, and status do not mutate a target. Privileged
changes require a root SSH user or non-interactive `sudo`; Bebop neither
prompts for nor stores passwords. A target-side `/run/lock/bebop.lock` flock
lease serializes built-in applies and releases automatically if its SSH/session
process dies. It rebuilds the plan immediately before confirmation, checks
module preconditions immediately before selected actions, verifies each, then
re-inspects and re-plans.

SSH hardening is fail-closed: the connected user must have an authorized key,
the existing config must validate, and the Debian drop-in include must exist.
Bebop validates a temporary candidate before replacing only its own drop-in;
it verifies the effective `sshd -T` values, and it blocks root-only SSH sessions
rather than disable their recovery path.

M0/M3 does not partition, format, resize, mount, or erase disks; alter routers,
DNS, or firewall rules; install an OS; collect telemetry; or use AI/LLM APIs.
M3 may manage only declared Compose projects under its target deployment root;
it never removes Compose volumes, arbitrary persistent data, router state, or
unrelated Docker projects. See
[docs/SAFETY.md](docs/SAFETY.md) for the exact boundary.

`doctor` and `status` report unmounted whole disks discovered through structured
`lsblk` data. Their only advice is to configure and mount storage separately;
they never generate a storage mutation.

## Development

```sh
make format
make check
make test-race
make build
make cross
make test-integration
make test-ssh-integration
make test-compose-integration
```

Integration tests are opt-in and need a running Docker daemon. `make
test-integration` runs local inspect in a disposable Debian container. `make
test-ssh-integration` builds temporary Debian 12 and Ubuntu 24.04 SSH targets,
adds a test-only known host/key configuration, and exercises the real SSH
transport. Neither integration target runs systemd, so systemd-dependent apply
is deliberately not claimed as container coverage. `make
test-compose-integration` uses an opt-in, privileged nested Docker daemon. It
validates real staged transfer and Compose lifecycle behavior in a disposable
runtime, but it does not claim systemd coverage; the target is Docker-in-Docker
rather than a full Debian/Ubuntu systemd VM.

Read [the architecture](docs/ARCHITECTURE.md), [safety policy](docs/SAFETY.md),
[M0/M1 scope](docs/MILESTONE-0.md), [M2 scope](docs/MILESTONE-2.md),
[M3 scope](docs/MILESTONE-3.md), [services](docs/SERVICES.md), and
[roadmap](docs/ROADMAP.md) before
extending Bebop.
