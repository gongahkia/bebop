package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestDecodeDefaultsAndStrictValidation(t *testing.T) {
	actual, err := Decode(strings.NewReader("version = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, Defaults()) {
		t.Fatalf("defaults mismatch: %#v", actual)
	}
	for _, contents := range []string{
		"version = 2\n",
		"version = 1\nunknown = true\n",
		"version = 1\n[network]\nfirewall = 'ufw'\n",
		"version = 1\n[storage]\ndata_root = '../srv'\n",
		"version = 1\n[server]\nname = 'not allowed!'\n",
	} {
		if _, err := Decode(strings.NewReader(contents)); err == nil {
			t.Fatalf("expected configuration failure for %q", contents)
		}
	}
}

func TestStarterRoundTrips(t *testing.T) {
	actual, err := Decode(strings.NewReader(Starter()))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, Defaults()) {
		t.Fatalf("starter does not round trip: %#v", actual)
	}
}

func TestFingerprintUsesNormalizedDesiredState(t *testing.T) {
	first, err := Fingerprint(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	second, err := Fingerprint(Defaults())
	if err != nil || first != second {
		t.Fatalf("unstable configuration fingerprint: %q %q %v", first, second, err)
	}
	changed := Defaults()
	changed.Features.Docker = false
	third, err := Fingerprint(changed)
	if err != nil || third == first {
		t.Fatalf("desired config change did not affect fingerprint: %q %q %v", first, third, err)
	}
}

func TestServiceSchemaIsStrictAndNormalized(t *testing.T) {
	actual, err := Decode(strings.NewReader(`version = 1

[services.zulu]
type = "compose"
source = "services/zulu"

[services.alpha]
type = "compose"
source = "services/alpha"
state = "stopped"
health_timeout = "15s"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(actual.Services) != 2 || actual.Services[0].Name != "alpha" || actual.Services[1].Name != "zulu" || actual.Services[1].State != "running" || actual.Services[1].HealthTimeout != DefaultServiceHealthTimeout {
		t.Fatalf("service defaults/sorting failed: %#v", actual.Services)
	}
	for _, contents := range []string{
		"version = 1\n[services.Hello]\ntype = 'compose'\nsource = 'services/hello'\n",
		"version = 1\n[services.hello]\ntype = 'compose'\nsource = '../escape'\n",
		"version = 1\n[services.hello]\ntype = 'compose'\nsource = 'services/hello'\npassword = 'do-not-store-secrets-here'\n",
		"version = 1\n[services.hello]\ntype = 'compose'\nsource = 'services/hello'\nstate = 'restart'\n",
		"version = 1\n[services.hello]\ntype = 'compose'\nsource = 'services/hello'\nhealth_timeout = '0s'\n",
	} {
		if _, err := Decode(strings.NewReader(contents)); err == nil {
			t.Fatalf("expected invalid service configuration: %s", contents)
		}
	}
}
