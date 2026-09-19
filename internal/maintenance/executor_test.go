package maintenance

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/transport"
)

func TestParseAPTUpdateSimulation(t *testing.T) {
	for _, test := range []struct {
		name       string
		output     string
		total      int
		security   int
		classified string
	}{
		{name: "no updates", output: "Reading package lists...\n0 upgraded, 0 newly installed", total: 0, security: 0, classified: "known"},
		{name: "security updates detected", output: "Inst openssl [3.0] (3.0.1 Debian-Security:stable-security [amd64])\nInst curl [8.0] (8.1 Debian-Security:stable-security [amd64])", total: 2, security: 2, classified: "known"},
		{name: "mixed update origins remain conservative", output: "Inst openssl [3.0] (3.0.1 Debian-Security:stable-security [amd64])\nInst curl [8.0] (8.1 Debian:stable [amd64])", total: 2, security: 1, classified: "unknown"},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual := ParseAPTUpdateSimulation(test.output)
			if actual.Total != test.total || actual.Security != test.security || actual.SecurityClassification != test.classified {
				t.Fatalf("summary = %#v, want total=%d security=%d classification=%s", actual, test.total, test.security, test.classified)
			}
		})
	}
}

func TestUpdateCheckScriptsNeverInstallOrUpgradePackages(t *testing.T) {
	archRefresh := archCheckupdatesRefreshScript("/srv/bebop")
	archCheck := archCheckupdatesScript("/srv/bebop")
	for _, script := range []string{aptRefreshScript, aptUpdateSimulationScript, dnfRefreshScript, dnfUpdateCheckScript, dnfUpdateCountScript, enterpriseDNFRefreshScript, enterpriseDNFUpdateCheckScript, enterpriseDNFUpdateCountScript, zypperRefreshScript, zypperLeapPatchCheckScript, zypperTumbleweedUpdateCheckScript, archRefresh, archCheck} {
		for _, forbidden := range []string{"apt upgrade", "apt-get upgrade", "apt full-upgrade", "apt-get install", "dist-upgrade", "dnf5 install", "dnf5 upgrade", "dnf5 update", "dnf install", "dnf upgrade", "dnf update", "zypper --non-interactive install", "zypper --non-interactive patch ", "zypper --non-interactive up"} {
			if containsToken(script, forbidden) {
				t.Fatalf("update-awareness script contains forbidden mutation %q: %s", forbidden, script)
			}
		}
	}
	if !containsToken(aptUpdateSimulationScript, "apt-get -s") || !containsToken(aptRefreshScript, "apt-get update") || !containsToken(dnfUpdateCheckScript, "dnf5 -y check-upgrade") || !containsToken(dnfRefreshScript, "dnf5 -y makecache") || !containsToken(enterpriseDNFUpdateCheckScript, "dnf -y check-update") || !containsToken(enterpriseDNFRefreshScript, "dnf -y makecache") || !containsToken(zypperLeapPatchCheckScript, "zypper --non-interactive patch-check") || !containsToken(zypperTumbleweedUpdateCheckScript, "zypper --non-interactive --xmlout dup --dry-run") {
		t.Fatalf("update-awareness scripts lost explicit semantics: %q / %q", aptUpdateSimulationScript, aptRefreshScript)
	}
	for _, forbidden := range []string{"pacman -Sy", "pacman -Syu", "pacman -S ", "pacman -U", "pacman -R"} {
		if containsToken(archRefresh, forbidden) || containsToken(archCheck, forbidden) {
			t.Fatalf("Arch update-awareness script contains forbidden mutation %q: %s / %s", forbidden, archRefresh, archCheck)
		}
	}
	if !containsToken(archRefresh, "CHECKUPDATES_DB='/srv/bebop/checkupdates'") || !containsToken(archCheck, "checkupdates --nocolor --nosync") || containsToken(archRefresh, "/var/lib/pacman/sync") || containsToken(archCheck, "/var/lib/pacman/sync") {
		t.Fatalf("Arch checkupdates did not use its isolated database safely: %s / %s", archRefresh, archCheck)
	}
}

func TestArchCheckupdatesExitSemantics(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		available bool
		failed    bool
	}{
		{name: "updates available", available: true},
		{name: "no updates", err: &transport.ExitError{Code: 2}},
		{name: "operational failure", err: &transport.ExitError{Code: 1}, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			available, err := archUpdatesAvailable(test.err)
			if available != test.available || (err != nil) != test.failed {
				t.Fatalf("checkupdates result available=%t err=%v", available, err)
			}
		})
	}
}

func TestArchCheckupdatesMissingPrerequisiteIsActionable(t *testing.T) {
	if err := requireArchCheckupdates(context.Background(), missingCheckupdatesTransport{}); err == nil || !strings.Contains(err.Error(), "pacman-contrib") || !strings.Contains(err.Error(), "checkupdates") {
		t.Fatalf("missing checkupdates error was not actionable: %v", err)
	}
}

type missingCheckupdatesTransport struct{}

func (missingCheckupdatesTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	return transport.Result{}, errors.New("command not found")
}
func (missingCheckupdatesTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (missingCheckupdatesTransport) FileExists(context.Context, string) (bool, error) {
	return false, nil
}
func (missingCheckupdatesTransport) Description() string { return "missing-checkupdates" }

func TestZypperUpdateExitAndDistributionUpgradeSemantics(t *testing.T) {
	for _, test := range []struct {
		code                int
		available, security bool
		failed              bool
	}{{0, false, false, false}, {100, true, false, false}, {101, true, true, false}, {1, false, false, true}} {
		var err error
		if test.code != 0 {
			err = &transport.ExitError{Code: test.code}
		}
		available, security, operational := zypperPatchUpdatesAvailable(err)
		if available != test.available || security != test.security || (operational != nil) != test.failed {
			t.Fatalf("zypper exit %d = available=%t security=%t err=%v", test.code, available, security, operational)
		}
	}
	for _, test := range []struct {
		output    string
		available bool
	}{
		{`<?xml version="1.0"?><stream><message type="info">Nothing to do.</message></stream>`, false},
		{`<?xml version="1.0"?><stream><update-status><toinstall name="new-package"/></update-status></stream>`, true},
		{`<?xml version="1.0"?><stream><update-status><toremove name="old-package"/></update-status></stream>`, true},
	} {
		available, err := ParseZypperDistributionUpgrade(test.output)
		if err != nil || available != test.available {
			t.Fatalf("Tumbleweed solver result = %t, %v", available, err)
		}
	}
}

func TestDNF5UpdateExitSemantics(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		available bool
		failed    bool
	}{
		{name: "clear"},
		{name: "updates", err: &transport.ExitError{Code: 100}, available: true},
		{name: "failure", err: &transport.ExitError{Code: 1}, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			available, err := dnfUpdatesAvailable(test.err)
			if available != test.available || (err != nil) != test.failed {
				t.Fatalf("dnf result available=%t err=%v", available, err)
			}
		})
	}
	if strings.Contains(dnfUpdateCheckScript, "install") {
		t.Fatalf("DNF update check must not install packages: %s", dnfUpdateCheckScript)
	}
}

func TestEnterpriseDNFUpdateExitSemantics(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		available bool
		failed    bool
	}{
		{name: "clear"},
		{name: "updates", err: &transport.ExitError{Code: 100}, available: true},
		{name: "failure", err: &transport.ExitError{Code: 1}, failed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			available, err := dnfUpdatesAvailable(test.err)
			if available != test.available || (err != nil) != test.failed {
				t.Fatalf("DNF result available=%t err=%v", available, err)
			}
		})
	}
}

func containsToken(value, token string) bool {
	return len(value) >= len(token) && stringContains(value, token)
}

func stringContains(value, token string) bool {
	for index := 0; index+len(token) <= len(value); index++ {
		if value[index:index+len(token)] == token {
			return true
		}
	}
	return false
}
