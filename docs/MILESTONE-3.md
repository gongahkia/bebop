# M3: deterministic service runtime

M3 turns Bebop's host converger into a small self-hosted workload operator
without changing its agentless or local-first model. The controller keeps
desired configuration, source manifests, plan artifacts, and the optional local
secret HMAC key; ordinary Linux targets run only Docker and the user's Compose
workloads.

## What M3 adds

- Strict `[services.NAME]` Compose declarations with `running`, `stopped`, and
  `absent` lifecycle states.
- Canonical, byte-oriented source manifests with sorted paths, normalized
  executable-bit policy, SHA-256 deployment digest, source-size guards, and
  symlink/special-file/traversal protection.
- A staged transport deployment under `storage.data_root/services/<name>`:
  archive transfer, mode/digest validation, `docker compose config -q`, atomic
  `current` activation, project-scoped reconciliation, and no release cleanup.
- Compose v2 capability inspection and optional apt package convergence through
  the existing Docker module.
- Structured runtime facts from Docker project labels and container state,
  semantic service actions, health-aware bounded verification, source and
  runtime drift correction, service status, and doctor diagnostics.
- Service input and target runtime state in canonical saved-plan validation.
  Source or secret rotation is refused before connection; target deployment or
  runtime changes are refused as relevant observed-state drift.
- A narrow `secret_env_file` convention whose values never enter plans, normal
  output, history, or logs, plus disposable nested-Docker lifecycle coverage.

## Explicit boundaries

M3 is not an application catalog, image builder, Compose feature-completion
project, Kubernetes layer, public-ingress system, secret manager, backup engine,
host migration tool, volume manager, daemon, cloud service, or plugin runtime.
It neither deletes Compose volumes nor runs `docker compose down -v`.

Mutable image tags remain a user-controlled runtime risk: a source manifest can
remain unchanged while an unpinned tag resolves differently when Docker pulls
it. Use immutable digests for the strongest reproducibility. Full rollback is
also deliberately future work; releases are retained, but Bebop does not choose
or automatically activate an older release.

## Integration tiers

`make test`, `make test-race`, and the regular unit suite do not require Docker.
M2's opt-in Debian and SSH-container tests remain. `make
test-compose-integration` starts a privileged nested Docker daemon, installs
only GNU test utilities in that disposable target, and exercises staged deploy,
health, runtime and deployment drift, update, stop, and volume-preserving
removal. It is real Compose coverage, but not a systemd-capable Debian/Ubuntu
VM; M3 does not claim that missing tier as completed.
