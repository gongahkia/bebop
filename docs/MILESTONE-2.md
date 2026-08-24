# M2: remote control plane and portable plans

M2 extends the M0/M1 `inspect -> plan -> apply -> verify -> no-op` engine for
people managing several existing Linux servers from one controller. Targets are
still agentless and reached only through the user's normal OpenSSH setup.

## Controller layout and inventory

The default inventory is `bebop.hosts.toml` beside the controller's
`bebop.toml`. Its strict version-1 schema is:

```toml
version = 1

[hosts.pi]
target = "ssh://pi@raspberrypi.local"
config = "hosts/pi.toml"
```

`target` is a safe `local` or `ssh://user@host[:port]` target. `config` is
optional and relative to the inventory directory; it cannot be absolute or
escape with `..`. It selects one complete desired-state config—M2 deliberately
does not add config inheritance or deep merge semantics. Explicit `--config`
wins. Inventory output is sorted and atomically replaced; it is safe to commit
but must contain no passwords, private keys, or tokens.

`host add NAME --target TARGET [--config PATH]`, `host list`, `host show NAME`,
and `host remove NAME --yes` manage only this controller file. A host reference
accepted by normal commands can be either an inventory alias or a literal
target. Supplying both an alias and `--target` is rejected as ambiguous.

## Preflight and fleet reads

`bootstrap HOST` is read-only. It resolves the normal target, uses the ordinary
inspection flow, and reports reachability/authentication, supported OS and
architecture, apt/dpkg, systemd, non-interactive root access, SSH safety, data
root, Docker, and Tailscale readiness. It does not install Docker, Tailscale,
or application services. SSH errors are categorized as DNS, timeout, refused,
host-key, authentication, client, sudo, or remote-command failures.

`doctor --all` and `status --all` read sorted inventory hosts with a bounded
worker pool (`--parallel N`, default 4). They retain a result for every host,
including failures, then exit non-zero if any requested host failed. Fleet apply
is intentionally absent.

Exit status is `0` on success; `2` for invalid local input/config/inventory or
unsupported artifact schema; `3` for target/transport or fleet-read failure;
`4` for blocked, stale, tampered, or wrong-host plans; and `5` for privilege,
lock, apply, or verification failure. Other uncategorized controller failures
remain `1`.

## Portable plan contract

`plan HOST --out FILE` writes schema version 1 JSON. The artifact stores:

- controller version, alias, and exact transport target;
- normalized config and its SHA-256 fingerprint;
- machine identity (machine ID when available; hostname/OS fallback);
- a SHA-256 fingerprint of relevant observed convergence state;
- the ordered plan, risk/dependency/precondition metadata, and plan fingerprint;
- an artifact SHA-256 fingerprint over every preceding semantic field.

Canonical artifact bodies have fixed struct field order and ordered slices; no
timestamps, map iteration, or network-derived ordering participate. The pretty
file is reproducible for identical inputs.

`apply --plan FILE` first validates schema and self-hashes. It validates the
current desired config before connecting, checks an existing recorded inventory
alias still points to the reviewed endpoint, re-inspects, checks target identity
and relevant-state drift, regenerates the plan, and requires its fingerprint to
match. Only the regenerated plan is dispatched to registered modules. Changed
memory, kernel, free space, and time do not stale a plan; changed planner/module
or warning inputs do. A changed local config, Docker state, endpoint alias, or
machine identity does.

## Mutation coordination

Built-in local/SSH transports hold `/run/lock/bebop.lock` with `flock` during a
non-empty apply. The live lease spans action preconditions, action execution,
verification, and convergence re-plan. A concurrent Bebop apply fails before
module execution. Kernel lock release prevents a crash from leaving a permanent
lock; this is not distributed consensus and does not control non-Bebop writers.

The base data-root creation, Docker install, and Tailscale install actions have
narrow immediate preconditions. Existing atomic SSH candidate validation remains
in place. These safeguards reduce, but cannot eliminate, remote TOCTOU races;
M2 makes no transactional or generalized rollback claim.

## Testing boundary

Unit and high-fidelity tests cover inventory atomicity/stability, artifact
canonicalization/tampering/stale config/state/wrong host, regenerated semantic
plans, apply locking, and fleet ordering/partial failure/cancellation. Explicit
Docker integration uses a disposable local Debian inspect container and
temporary Debian 12 plus Ubuntu 24.04 SSH containers with a test-only key and
strict temporary known-host entry. Those containers do not run systemd, so the
integration tier validates real SSH inspection and OS recognition rather than
claiming systemd service convergence coverage.
