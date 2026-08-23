# Architecture

Bebop's execution model is deliberately one-way:

```text
Target URI -> Transport -> Inspector -> HostFacts --+
                                                 +-> Planner -> immutable Plan
bebop.toml -> strict Config ---------------------+                 |
                                                                   v
                                                      explicit Apply / verify
                                                                   |
                                                                   v
                                                     re-inspect and re-plan
```

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
