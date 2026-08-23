package modules

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
	"github.com/bebop-home/bebop/internal/plan"
)

func TestSSHHardeningFailsClosedAndCandidateValidatesBeforeInstall(t *testing.T) {
	base := facts.HostFacts{SudoAvailable: true, SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, DropInSupported: true}}
	changes, _, err := (SSH{}).Plan(base, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !strings.Contains(changes[0].Blocked, "authorized_keys") {
		t.Fatalf("expected key safety block: %#v", changes)
	}
	base.SSH.AuthorizedKeysPresent = true
	base.SSH.ConfigValid = false
	changes, _, _ = (SSH{}).Plan(base, config.Defaults())
	if !strings.Contains(changes[0].Blocked, "does not validate") {
		t.Fatalf("expected validation block: %#v", changes[0])
	}
	base.SSH.ConfigValid = true
	changes, _, _ = (SSH{}).Plan(base, config.Defaults())
	script := changes[0].Action.Script
	validate := strings.Index(script, "sshd -t")
	install := strings.Index(script, "mv -f")
	if validate < 0 || install < 0 || validate > install {
		t.Fatalf("candidate must validate before install: %s", script)
	}
	if !strings.Contains(script[:install], "sshd -T | grep -Fqx 'passwordauthentication no'") || !strings.Contains(changes[0].Action.Resource, "00-bebop.conf") {
		t.Fatalf("candidate must prove effective values before installing: %s", script)
	}
}

func TestPlannedScriptsPassPOSIXShellSyntax(t *testing.T) {
	host := facts.HostFacts{EffectiveUser: "pi", SudoAvailable: true, OS: facts.OS{ID: "debian", VersionID: "12", VersionCodename: "bookworm"}, SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, DropInSupported: true, AuthorizedKeysPresent: true}, DataRoot: facts.Directory{Path: "/srv/bebop's"}}
	cfg := config.Defaults()
	cfg.Storage.DataRoot = host.DataRoot.Path
	scripts := []string{updatesScript, tailscaleInstallScript("debian", "bookworm")}
	for _, capability := range []interface {
		Plan(facts.HostFacts, config.Config) ([]plan.Change, []plan.Warning, error)
	}{Base{}, Docker{}, SSH{}} {
		changes, _, err := capability.Plan(host, cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, change := range changes {
			scripts = append(scripts, change.Action.Script)
		}
	}
	for _, script := range scripts {
		command := exec.Command("sh", "-n")
		command.Stdin = bytes.NewBufferString(script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("invalid planned shell script: %v\n%s\n%s", err, script, output)
		}
	}
}

func TestSSHHardeningBlocksEarlierUnknownDropIn(t *testing.T) {
	host := facts.HostFacts{EffectiveUser: "pi", SudoAvailable: true, SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, DropInSupported: true, FirstDropIn: "00-a-vendor.conf", AuthorizedKeysPresent: true}}
	changes, _, err := (SSH{}).Plan(host, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !strings.Contains(changes[0].Blocked, "earlier SSH drop-in") {
		t.Fatalf("precedence risk was not blocked: %#v", changes)
	}
}

func TestSSHHardeningRefusesRootOnlyRemoteAccess(t *testing.T) {
	host := facts.HostFacts{EffectiveUser: "root", SudoAvailable: true, SSH: facts.SSH{Installed: true, Service: "ssh.service", ConfigValid: true, DropInSupported: true, AuthorizedKeysPresent: true}}
	changes, _, err := (SSH{}).Plan(host, config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || !strings.Contains(changes[0].Blocked, "account is root") {
		t.Fatalf("root SSH safety was not blocked: %#v", changes)
	}
}
