# M0/M1: deterministic engine and first Linux convergence path

The implemented path is:

```text
inspect -> HostFacts + bebop.toml -> deterministic plan -> explicit apply
        -> per-change verification -> fresh inspection -> no executable changes
```

| Module | Observed state | Desired state and verification |
| --- | --- | --- |
| Base filesystem | directory existence, mode, UID/GID | root-owned `0750` data root; `stat` verification |
| Updates | package database and effective apt periodic settings | `unattended-upgrades` plus Bebop config; apt query/config verification |
| Docker | `docker.io`, service enable/activity, privileged `docker info` | package and responsive enabled service |
| Tailscale | package, service, status JSON | official mapped repository package and enabled daemon; auth stays manual |
| SSH | server, service, `sshd -t`, include, key presence | validated Bebop drop-in; unsafe state is blocked |

Unmounted whole disks are observed with structured `lsblk` output and surfaced
as warnings only; no storage module or storage action exists in M0/M1.

The reviewed Tailscale map covers Debian/Raspberry Pi OS Bookworm or Trixie and
Ubuntu Jammy or Noble. Other supported host versions can use base, updates, and
Docker, but Tailscale installation is blocked until its mapping is reviewed.

`plan` is read-only and `--show-commands` shows exact scripts. `apply` shows a
fresh plan and asks for confirmation; `--yes` removes only the prompt. It
verifies every action then re-plans. Remaining executable work exits non-zero;
a Tailscale authentication warning is not package convergence failure.

The unit suite uses fixtures, fake transports, and transition models rather
than the development host. Its idempotence test applies and verifies all initial
module changes through a recording fake transport, updates observed state,
proves the fresh plan has zero executable changes, then proves a second apply
performs zero transport operations.
