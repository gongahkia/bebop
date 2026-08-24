package modules

import (
	"context"
	"fmt"
	"strings"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
	storagepolicy "github.com/bebop-home/bebop/internal/storage"
	"github.com/bebop-home/bebop/internal/transport"
)

// Storage manages only an explicitly declared mount of an existing filesystem.
// It never creates a filesystem, chooses a device, or changes Docker storage.
type Storage struct{}

func (Storage) Name() string { return "storage" }

func (Storage) Plan(host facts.HostFacts, cfg config.Config) ([]plan.Change, []plan.Warning, error) {
	changes := make([]plan.Change, 0)
	for _, assessment := range storagepolicy.AssessAll(cfg.Storage, host.Storage) {
		resource := assessment.Resource
		if assessment.State == storagepolicy.Ready {
			continue
		}
		if !resource.ManagedMount || (assessment.State != storagepolicy.Missing && assessment.State != storagepolicy.RootSpill) {
			changes = append(changes, blockedStorageChange(resource, assessment))
			continue
		}
		mountpointID := "storage." + resource.Name + ".mountpoint"
		configureID := "storage." + resource.Name + ".mount-config"
		changes = append(changes,
			plan.Change{ID: mountpointID, Module: "storage", Summary: "prepare declared storage mount point", Reason: assessment.Detail, Risk: plan.Privileged, RequiresRoot: true, Current: string(assessment.State), Desired: "empty non-symlink directory " + resource.Mount, Preconditions: []plan.Precondition{{ID: mountpointID + ".safe", Description: "mount point is absent or an empty non-symlink directory", Script: mountpointSafeScript(resource.Mount)}}, Action: plan.Action{Kind: "storage.prepare-mountpoint", Resource: resource.Name, Script: "install -d -m 0750 -o root -g root -- " + transport.ShellQuote(resource.Mount)}, Verification: "mount point is an empty non-symlink directory"},
			plan.Change{ID: configureID, Module: "storage", Summary: "persist declared filesystem mount", Reason: "managed_mount is enabled for an already-formatted filesystem", Risk: plan.Privileged, RequiresRoot: true, Current: "no Bebop-owned fstab entry", Desired: "UUID " + resource.FilesystemUUID + " mounted at " + resource.Mount, Dependencies: []string{mountpointID}, Preconditions: []plan.Precondition{{ID: configureID + ".safe", Description: "no conflicting fstab mount entry exists", Script: fstabSafeScript(resource)}}, Action: plan.Action{Kind: "storage.configure-mount", Resource: resource.Name, Script: fstabWriteScript(resource)}, Verification: "a validated Bebop-owned fstab entry identifies the declared filesystem UUID"},
			plan.Change{ID: "storage." + resource.Name + ".mount", Module: "storage", Summary: "mount declared storage filesystem", Reason: "managed mount is not active", Risk: plan.Privileged, RequiresRoot: true, Current: string(assessment.State), Desired: "mounted writable filesystem UUID " + resource.FilesystemUUID, Dependencies: []string{configureID}, Preconditions: []plan.Precondition{{ID: "storage." + resource.Name + ".mount-safe", Description: "mount point remains safe and fstab entry remains compatible", Script: mountpointSafeScript(resource.Mount) + "\n" + fstabConfiguredScript(resource)}}, Action: plan.Action{Kind: "storage.mount", Resource: resource.Name, Script: "mount " + transport.ShellQuote(resource.Mount)}, Verification: "configured filesystem UUID is mounted writable at its declared mount point"},
		)
		for index := len(changes) - 3; index < len(changes); index++ {
			rootBlocked(&changes[index], host.SudoAvailable)
		}
	}
	return changes, nil, nil
}

func blockedStorageChange(resource config.StorageResource, assessment storagepolicy.Assessment) plan.Change {
	return plan.Change{ID: "storage." + resource.Name + ".blocked", Module: "storage", Summary: "storage resource requires operator attention", Reason: assessment.Detail, Risk: plan.Privileged, RequiresRoot: true, Current: string(assessment.State), Desired: "writable filesystem UUID " + resource.FilesystemUUID + " at " + resource.Mount, Action: plan.Action{Kind: "storage.blocked", Resource: resource.Name}, Verification: "none; resolve storage placement manually and re-plan", Blocked: "storage resource " + resource.Name + " is " + string(assessment.State) + "; Bebop will not format, repartition, unmount, or replace filesystems"}
}

func (Storage) Apply(ctx context.Context, tr transport.Transport, _ config.Config, change plan.Change) error {
	return runAction(ctx, tr, change, "storage.prepare-mountpoint", "storage.configure-mount", "storage.mount")
}

func (Storage) Verify(ctx context.Context, tr transport.Transport, cfg config.Config, change plan.Change) error {
	resource, found := storagepolicy.Find(cfg.Storage, change.Action.Resource)
	if !found {
		return fmt.Errorf("storage module cannot verify unknown resource %q", change.Action.Resource)
	}
	switch change.Action.Kind {
	case "storage.prepare-mountpoint":
		return verify(ctx, tr, mountpointSafeScript(resource.Mount))
	case "storage.configure-mount":
		return verify(ctx, tr, fstabConfiguredScript(resource))
	case "storage.mount":
		return verify(ctx, tr, storagepolicy.ReadyPrecondition(resource))
	default:
		return fmt.Errorf("storage module refuses verification for %q", change.Action.Kind)
	}
}

func mountpointSafeScript(mount string) string {
	quoted := transport.ShellQuote(mount)
	return "test ! -L " + quoted + "\nif test -e " + quoted + "; then test -d " + quoted + "; fi\nif test -d " + quoted + " && find " + quoted + " -xdev -mindepth 1 -print -quit | grep -q .; then exit 1; fi"
}

func fstabLine(resource config.StorageResource) string {
	filesystem := resource.FilesystemType
	if filesystem == "" {
		filesystem = "auto"
	}
	return "UUID=" + resource.FilesystemUUID + " " + resource.Mount + " " + filesystem + " defaults,nofail 0 2 # bebop-storage:" + resource.Name
}

func fstabExactScript(resource config.StorageResource) string {
	return "grep -Fqx -- " + transport.ShellQuote(fstabLine(resource)) + " /etc/fstab"
}

func fstabConfiguredScript(resource config.StorageResource) string {
	return "state=$(\n" + storagepolicy.MountConfigProbe(resource) + "\n)\ntest \"$state\" = exact -o \"$state\" = external"
}

func fstabSafeScript(resource config.StorageResource) string {
	return "state=$(\n" + storagepolicy.MountConfigProbe(resource) + "\n)\ntest \"$state\" = absent -o \"$state\" = exact -o \"$state\" = external"
}

func fstabWriteScript(resource config.StorageResource) string {
	line := transport.ShellQuote(fstabLine(resource))
	return strings.Join([]string{
		"state=$(\n" + storagepolicy.MountConfigProbe(resource) + "\n)",
		"case \"$state\" in exact|external) exit 0 ;; absent) ;; *) exit 1 ;; esac",
		"temporary=$(mktemp /etc/.bebop-fstab.XXXXXX)",
		"trap 'rm -f -- \"$temporary\"' EXIT",
		"cat /etc/fstab > \"$temporary\"",
		"printf '%s\\n' " + line + " >> \"$temporary\"",
		"findmnt --verify --tab-file \"$temporary\" >/dev/null",
		"chmod 0644 -- \"$temporary\"",
		"mv -f -- \"$temporary\" /etc/fstab",
		"trap - EXIT",
	}, "\n")
}
