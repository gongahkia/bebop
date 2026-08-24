# Safety policy

## Authority, inventory, and secrets

Read-only inspection uses the normal target identity. Privileged work requires
a root SSH user or non-interactive `sudo -n`. Bebop neither prompts for,
captures, stores, logs, nor passes sudo/SSH passwords. It accepts no Tailscale
auth key in M0/M1. Existing SSH keys, agent state, `known_hosts`, and SSH config
remain under the user's control.

All privileged shell content is a reviewed module template. The only dynamic
current field is a validated data-root path, passed through POSIX single-quote
escaping. SSH target users, hosts, and ports are validated before becoming
process arguments. No configuration field is an arbitrary command.

`bebop.hosts.toml` is local controller metadata only: alias, safe target URI,
and optional relative config path. Its atomic writer is deterministic and it
does not support passwords, private keys, auth tokens, or arbitrary SSH options.
Host removal changes only that local file and never contacts a target. Bebop
continues to use the installed OpenSSH client, the user's SSH config, known
hosts, agents, ProxyJump, and identity selection; it never enables unsafe host
key defaults.

## What Bebop may change

An approved plan may create or non-recursively correct the configured data
root; install Debian packages; manage `docker.service` and `tailscaled.service`;
create `52-bebop-auto-upgrades`; create Tailscale's documented keyring/list;
and create `/etc/ssh/sshd_config.d/00-bebop.conf`.

Managed configuration uses temporary candidates and atomic `mv` where
practical, and carries a `Managed by Bebop` header. Bebop does not claim
ownership of `/etc/ssh/sshd_config`, arbitrary apt files, or Docker projects.

M3 may manage a declared Compose project's replaceable deployment source below
`storage.data_root/services/<service>`. It stages, validates, and atomically
activates the `current` release before project-scoped Compose reconciliation.
It can replace a known Bebop release tree, but refuses a `current` path that is
not a symlink into that service's release directory. It never treats arbitrary
directories as deployment state.

M3 service absence runs `docker compose down --remove-orphans` **without**
`-v`, removes only the active `current` link, and retains release trees. Bebop
does not invoke `docker volume rm`, `docker compose down -v`, or recursive
deletion of bind-mounted or application data. Relative bind mounts are rejected
because they could write persistent data into a replaceable release tree. Use a
named volume or explicit absolute external target path rather than rely on
retained deployment files as a backup boundary.

During a non-empty built-in apply, Bebop holds a target-side advisory flock at
`/run/lock/bebop.lock` through the full apply/verify/replan window. A second
Bebop apply fails before module execution while the lease is held. The lock is
released by the kernel if the controller, SSH session, or lock process dies;
read-only commands do not acquire it. A host that bypasses Bebop can still
change state, so lock acquisition is paired with fresh inspection and narrow
module preconditions rather than presented as a transaction.

## SSH and networking

SSH hardening never rewrites the primary configuration. It refuses to disable
password authentication without a key for the connected user, a valid existing
`sshd` configuration, and a known standard drop-in include. It validates an
included temporary candidate before installation, then reloads SSH rather than
restarting it. It also blocks a root SSH session because `PermitRootLogin no`
would remove that session's recovery path. `--yes` cannot bypass a block.

Firewall discovery is informational only. Bebop never enables UFW, flushes
rules, changes nftables/iptables/firewalld, changes router settings, opens ports,
or configures public ingress.

Compose may publish ports the user declares. Bebop statically blocks duplicate
fixed host ports across its own declared services and labels those changes as
network-sensitive, but it does not inspect or reconfigure router/NAT state and
cannot reserve a port used by an unrelated Docker project. Docker Compose is
always called with structured arguments, a fixed safe PATH, `env -i`, and
`docker --context default`; no service, project, source, or port string is
used as unquoted shell code or an unvalidated command-line option.

## Service source and secret boundary

Service source paths are controller-relative and contained within the config
directory. Bebop rejects absolute/traversal paths, symlinks, special files,
ambiguous Compose sources, and reserved secret filenames. It transfers only an
archive it created from a validated sorted manifest, then verifies each staged
file's digest and normalized mode before activation. It does not accept
controller-provided tar archives or target-side Git checkouts.

`secret_env_file` is a restricted reference, not a TOML secret field. Its value
is transferred only into `.bebop-secret.env` at mode `0600`; it is excluded from
human/JSON plans, artifacts, status, doctor, error messages, and normal logs.
The controller stores a private local HMAC key in `.bebop/cache`; artifacts
contain a keyed marker, not a direct secret digest. A changed source or secret
marker makes a saved plan stale before Bebop connects. Losing that local key is
safe: the user must re-plan rather than apply an old secret-bearing plan.

## Saved-plan boundary

Saved plans are versioned, deterministic JSON artifacts with a SHA-256
self-fingerprint. Before `apply --plan`, Bebop rejects unknown schema versions,
tampered content, changed normalized configuration, a changed machine identity,
or changed relevant convergence state. It then regenerates the plan from fresh
facts and applies that result, not shell text deserialized from the artifact.

Relevant state includes only current planning and warning inputs. It excludes
volatile kernel, memory, free-space, timestamps, and similar telemetry. Machine
ID is preferred for wrong-host protection; if unavailable Bebop falls back to
hostname plus OS identity. If that fallback cannot match, safety takes priority
and saved apply is refused. Neither this guard, the lock, nor preconditions can
make arbitrary remote mutation transactional; another actor can still change a
host between checks, and Bebop reports subsequent divergence through verification.

For services, relevant state additionally includes configured service runtime,
active non-secret deployment digest, and the hidden keyed secret marker. A
manual container stop produces a semantic lifecycle correction; a manual edit
to a Bebop-owned active Compose file produces a source restoration. These
checks, target locking, and immediate deployment preconditions reduce TOCTOU
risk but do not make Docker operations transactional or provide rollback.

`status --all` and `doctor --all` are bounded-concurrency read operations. They
do not imply authorization to apply across a fleet, and one failed host is shown
alongside successful results before the command returns non-zero.

## Storage and exclusions

Bebop reports filesystem and selected directory state, and warns about unmounted
whole disks found through `lsblk --json`; it does not partition, format, mount,
resize, encrypt, erase, or automate disks. It also does not install an OS,
rotate SSH credentials, delete arbitrary user data,
perform `apt upgrade`, use convenience installer pipes, send telemetry, depend
on a Bebop cloud, or invoke an LLM/AI API.
