package facts

import "testing"

func TestPlatformPoliciesAreCompleteAndStable(t *testing.T) {
	policies := PlatformPolicies()
	if len(policies) != 21 {
		t.Fatalf("reviewed platform count = %d, want 21", len(policies))
	}
	seen := map[string]bool{}
	for _, policy := range policies {
		if seen[policy.Key] {
			t.Fatalf("duplicate platform policy %q", policy.Key)
		}
		seen[policy.Key] = true
		if err := policy.Validate(); err != nil {
			t.Fatalf("platform policy %s invalid: %v", policy.Key, err)
		}
		for _, capability := range RequiredCapabilities() {
			if policy.Capability(capability) == "" {
				t.Fatalf("platform policy %s omitted capability %s", policy.Key, capability)
			}
		}
	}
	for _, unsupported := range []string{"gentoo", "slackware", "chimera", "nixos", "guix", "ol", "amzn"} {
		if len(ReviewedPlatformsForID(unsupported)) != 0 {
			t.Fatalf("unsupported OS %q appeared in the reviewed matrix", unsupported)
		}
	}
}

func TestPlatformMatrixKeepsPackageManagerAndInitOrthogonal(t *testing.T) {
	tests := []struct {
		key, manager string
		init         InitSystem
	}{
		{"debian-12", "apt", InitSystemSystemd},
		{"devuan-6", "apt", InitSystemSysV},
		{"arch", "pacman", InitSystemSystemd},
		{"artix", "pacman", InitSystemDinit},
		{"alpine-3.24", "apk", InitSystemOpenRC},
		{"void", "xbps", InitSystemRunit},
	}
	policies := map[string]PlatformPolicy{}
	for _, policy := range PlatformPolicies() {
		policies[policy.Key] = policy
	}
	for _, test := range tests {
		policy, ok := policies[test.key]
		if !ok || policy.PackageManager != test.manager || policy.InitSystem != test.init {
			t.Fatalf("%s policy = %#v", test.key, policy)
		}
	}
}

func TestPlatformPolicyReleaseArchitectureAndLibcGatesFailClosed(t *testing.T) {
	for _, test := range []struct {
		name       string
		os         OS
		arch, libc string
		want       bool
	}{
		{"fedora-44", OS{ID: "fedora", VersionID: "44", Supported: true}, "amd64", "", true},
		{"fedora-45", OS{ID: "fedora", VersionID: "45", Supported: true}, "amd64", "", false},
		{"alpine-patch", OS{ID: "alpine", VersionID: "3.24.99", Supported: true}, "arm64", "", true},
		{"alpine-rc", OS{ID: "alpine", VersionID: "3.24.0_rc1", Supported: true}, "amd64", "", false},
		{"void-musl", OS{ID: "void", Supported: true}, "arm64", "musl", true},
		{"void-libc", OS{ID: "void", Supported: true}, "arm64", "uclibc", false},
		{"devuan-sysv-platform", OS{ID: "devuan", VersionID: "6", VersionCodename: "excalibur", Supported: true}, "arm64", "", true},
		{"artix-rolling", OS{ID: "artix", BuildID: "rolling", Supported: true}, "amd64", "", true},
		{"artix-arm64", OS{ID: "artix", BuildID: "rolling", Supported: true}, "arm64", "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.os.IsSupported() && test.os.SupportsArchitecture(test.arch) && LibcSupported(test.os, test.libc); got != test.want {
				t.Fatalf("policy result = %t for %#v %s/%s, want %t", got, test.os, test.arch, test.libc, test.want)
			}
		})
	}
	unsupported, err := ParseOSRelease("ID=example\nID_LIKE=debian\nVERSION_ID=12\n")
	if err != nil || unsupported.IsSupported() {
		t.Fatalf("ID_LIKE unexpectedly granted support: %#v, %v", unsupported, err)
	}
}

func TestPlatformAutomaticUpdatePolicyIsExplicit(t *testing.T) {
	unsupported := map[string]bool{"arch": true, "void": true, "artix": true}
	for _, policy := range PlatformPolicies() {
		wantUnsupported := unsupported[policy.Key]
		gotUnsupported := policy.AutomaticUpdates == AutomaticUpdatesUnsupported && policy.Capability(CapabilityAutomaticUpdates) == CapabilityIntentionallyUnsupported
		if gotUnsupported != wantUnsupported {
			t.Fatalf("automatic-update policy for %s = %s/%s, want unsupported=%t", policy.Key, policy.AutomaticUpdates, policy.Capability(CapabilityAutomaticUpdates), wantUnsupported)
		}
	}
}
