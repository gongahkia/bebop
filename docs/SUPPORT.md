# Reviewed platform support

`internal/facts/platform.go` is Bebop's compile-time reviewed support matrix.
It is the authority for exact OS/release identity, architecture, package
manager, target init, release model, root-persistence requirements, and
automatic-update policy. Package names, repository definitions, and service
scripts remain in their capability modules.

| Platform | Architectures | Package manager | Target init | Release model | Automatic updates | Important restriction |
| --- | --- | --- | --- | --- | --- | --- |
| Debian 12, 13 | amd64, arm64 | apt + dpkg | systemd | fixed | supported | exact reviewed release |
| Ubuntu 22.04, 24.04 | amd64, arm64 | apt + dpkg | systemd | fixed | supported | exact reviewed release |
| Raspberry Pi OS 12, 13 | amd64, arm64 | apt + dpkg | systemd | fixed | supported | exact reviewed release |
| Fedora 43, 44 | amd64, arm64 | dnf5 + rpm | systemd | fixed | supported | exact reviewed release |
| Rocky Linux 9.8, 10.2 | amd64, arm64 | dnf + rpm | systemd | fixed | supported | exact reviewed release |
| AlmaLinux 9.8, 10.2 | amd64, arm64 | dnf + rpm | systemd | fixed | supported | exact reviewed release |
| CentOS Stream 9, 10 | amd64, arm64 | dnf + rpm | systemd | stream | supported | exact Stream platform identity |
| openSUSE Leap 16.0 | amd64, arm64 | zypper + rpm | systemd | fixed | supported | mutable host required |
| openSUSE Tumbleweed | amd64, arm64 | zypper + rpm | systemd | rolling | supported | mutable host required |
| Arch Linux | amd64 | pacman | systemd | rolling | intentionally unsupported | use a reviewed full upgrade manually |
| Alpine Linux 3.24.x | amd64, arm64 | apk | OpenRC | fixed | supported | persistent SYS-style root and preinstalled `flock`, `lsblk`, `findmnt` |
| Void Linux | amd64, arm64; glibc or musl | XBPS | runit | rolling | intentionally unsupported | persistent host and reviewed libc repository |
| Devuan 6 Excalibur | amd64, arm64 | apt + dpkg | SysVinit | fixed | supported | exact Excalibur merged-repository policy |
| Artix Linux | amd64 | pacman | dinit | rolling | intentionally unsupported | official Artix repositories only |

Every platform in the matrix has an explicit reviewed path for inspection,
bootstrap, doctor, status, plan/apply, saved-plan apply, data root, Docker,
Compose V2, Tailscale, SSH hardening, storage assessment and managed mounts,
Compose services, backups/restores, maintenance backup/doctor/update-check,
notifications, and recipes. Automatic updates are the explicit exception for
Arch, Void, and Artix: requesting them blocks planning instead of creating an
unattended rolling-upgrade path.

The target init and package manager are independent policy dimensions. For
example, Debian is apt/systemd while Devuan is apt/SysVinit; Arch is
pacman/systemd while Artix is pacman/dinit. Controller-side maintenance
scheduling remains a controller concern and is not selected from this table.

The matrix does not grant support through `ID_LIKE`, an installed package
manager, or the mere presence of an init executable. Rolling targets are
identified by their exact official identity rather than a snapshot date. Gentoo
remains unsupported: the reviewed binary-only contract still lacks required
official Tailscale binary packages.
