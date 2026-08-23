# Safety policy

## Authority and secrets

Read-only inspection uses the normal target identity. Privileged work requires
a root SSH user or non-interactive `sudo -n`. Bebop neither prompts for,
captures, stores, logs, nor passes sudo/SSH passwords. It accepts no Tailscale
auth key in M0/M1. Existing SSH keys, agent state, `known_hosts`, and SSH config
remain under the user's control.

All privileged shell content is a reviewed module template. The only dynamic
current field is a validated data-root path, passed through POSIX single-quote
escaping. SSH target users, hosts, and ports are validated before becoming
process arguments. No configuration field is an arbitrary command.

## What Bebop may change

An approved plan may create or non-recursively correct the configured data
root; install Debian packages; manage `docker.service` and `tailscaled.service`;
create `52-bebop-auto-upgrades`; create Tailscale's documented keyring/list;
and create `/etc/ssh/sshd_config.d/00-bebop.conf`.

Managed configuration uses temporary candidates and atomic `mv` where
practical, and carries a `Managed by Bebop` header. Bebop does not claim
ownership of `/etc/ssh/sshd_config`, arbitrary apt files, or Docker projects.

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

## Storage and exclusions

Bebop reports filesystem and selected directory state, and warns about unmounted
whole disks found through `lsblk --json`; it does not partition, format, mount,
resize, encrypt, erase, or automate disks. It also does not install an OS,
rotate SSH credentials, delete arbitrary user data,
perform `apt upgrade`, use convenience installer pipes, send telemetry, depend
on a Bebop cloud, or invoke an LLM/AI API.
