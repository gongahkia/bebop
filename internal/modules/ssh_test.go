package modules

import (
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/config"
	"github.com/bebop-home/bebop/internal/facts"
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
