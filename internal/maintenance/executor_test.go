package maintenance

import "testing"

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
	for _, script := range []string{aptRefreshScript, aptUpdateSimulationScript} {
		for _, forbidden := range []string{"apt upgrade", "apt-get upgrade", "apt full-upgrade", "apt-get install", "dist-upgrade"} {
			if containsToken(script, forbidden) {
				t.Fatalf("update-awareness script contains forbidden mutation %q: %s", forbidden, script)
			}
		}
	}
	if !containsToken(aptUpdateSimulationScript, "apt-get -s") || !containsToken(aptRefreshScript, "apt-get update") {
		t.Fatalf("update-awareness scripts lost explicit semantics: %q / %q", aptUpdateSimulationScript, aptRefreshScript)
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
