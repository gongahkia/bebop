# Architecture

Bebop's execution model is deliberately one-way. M2 adds only controller-side
inventory and portable review artifacts; targets remain ordinary Linux machines
with no Bebop daemon:

```text
inventory alias ─┐
literal target ──┼─> resolver -> Target -> Transport -> Inspector -> HostFacts --+
                 │                                                              +-> Planner -> immutable Plan
host config ─────┘                     strict Config --------------------------+              |
                                                                                                 ├─> render
                                                                                                 └─> canonical artifact
                                                                                                         |
later apply ───────────────────────────────────────────────────────────────────── fresh inspection + drift checks
                                                                                                         |
                                                                                              target flock lease
                                                                                                         |
                                                                                              apply / verify / re-plan
```

`internal/inventory` owns versioned `bebop.hosts.toml`: aliases, safe target
URIs, and relative controller config paths. It writes sorted TOML atomically.
`internal/resolve` turns both aliases and literal target URIs into the existing
`target.Target`, so transport and module execution paths remain singular.

`internal/target` parses only `local` or safe `ssh://user@host[:port]` URIs.
`internal/transport` is the boundary below the domain model. `Local` and `SSH`
both execute an explicit POSIX script request, preserve cancellation and exit
status, and provide file reads. The SSH implementation invokes system OpenSSH
with `BatchMode=yes`; it does not change host-key policy or SSH configuration.

`internal/inspect` is the sole observation layer. It turns `/etc/os-release`,
stable command output, package database state, systemd state, filesystem
metadata, and `tailscale status --json` into `facts.HostFacts`. Modules do not
scatter ad-hoc probes. Raspberry Pi OS (`ID=raspbian`) is normalized as the
`raspberry-pi-os` family rather than being incidentally treated as Debian.

`internal/config` decodes a versioned TOML schema with unknown fields rejected,
applies deterministic defaults, and validates names, enum values, and data-root
paths. Each `internal/modules` capability implements `Plan`, `Apply`, and
`Verify`. Plan has no transport, so it cannot mutate a target. Its changes have
stable IDs, observed and desired state, risk, root requirement, dependencies,
exact script, and verification description. Apply accepts only the reviewed
change and refuses unknown action kinds; it has no separate configuration-to-
shell path.

SSH hardening additionally distinguishes the managed file from effective
configuration. It uses an early `00-bebop.conf`, blocks if an earlier unknown
drop-in could win OpenSSH's first-value precedence, and tests `sshd -T` before
and after replacement.

The planner sorts module registration by module name and uses lexical Kahn
topological sorting for dependencies. Canonical plan JSON has no timestamps,
maps, filesystem traversal results, or network-derived ordering. Its SHA-256
fingerprint covers plan version, target, ordered changes, and ordered warnings;
it excludes its own fingerprint and facts that are not represented in a change.

`internal/apply` rejects blocks, applies the ordered actions, verifies each,
then requests a complete fresh inspection and plan. Remaining executable work
is a verification error. Immediate re-planning before confirmation narrows,
but cannot eliminate, concurrent external changes during apply.

To add a module, normalize new state in `HostFacts`, introduce strict desired
state only when supported, implement the module interface with stable IDs and
dependencies, register it in `modules.Default`, and add deterministic and
transition/idempotence tests. Do not let modules invoke ad-hoc SSH clients or
derive unvalidated shell fragments.

## M2 control-plane boundaries

`internal/preflight` is the shared read-only bootstrap/doctor assessment. It
uses the normal service inspection rather than an alternate SSH client and
reports classified DNS, timeout, refused, host-key, authentication, client,
sudo, and command failures. Inspector facts now include an optional machine ID
and a detected apt/dpkg capability.

`internal/artifact` defines a versioned JSON plan-file contract. Its ordered
canonical body has no timestamps or maps and is SHA-256 hashed. It records the
controller version, endpoint, optional alias, normalized config and fingerprint,
identity, relevant observed-state fingerprint, and complete plan. On a saved
apply, `internal/savedplan` validates schema/self-hash/current config, performs
a fresh normal inspection, checks identity and drift, regenerates the plan, and
passes only that regenerated plan to apply. Artifact scripts are therefore not
an execution authority, even if someone recomputes a self-hash.

Relevant state contains planner/module inputs and plan-warning inputs: OS,
architecture, apt/systemd/privilege state, module facts, firewall/storage
warnings, and data-root metadata. Kernel, memory, free space, timestamps, and
transport timing are excluded. Identity prefers machine ID and conservatively
falls back to hostname plus OS identity when it is unavailable.

`internal/apply` obtains a built-in transport flock lease for the full
apply/verify/replan interval, then evaluates any module-level preconditions
immediately before the action. Local and SSH transports hold
`/run/lock/bebop.lock` through a live process; a controller or SSH crash releases
the kernel lock. This narrows, but does not eliminate, out-of-band TOCTOU races.

`internal/fleet` runs independent read-only work in a bounded worker pool and
writes each result to its original sorted inventory index. `status --all` and
`doctor --all` retain individual errors and render all hosts before returning a
non-zero aggregate result. Fleet mutation is intentionally unsupported.
