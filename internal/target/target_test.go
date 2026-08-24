package target

import "testing"

func TestParseTarget(t *testing.T) {
	actual, err := Parse("ssh://pi@raspberrypi.local:2222")
	if err != nil {
		t.Fatal(err)
	}
	if actual.Kind != SSH || actual.User != "pi" || actual.Host != "raspberrypi.local" || actual.Port != 2222 || actual.String() != "ssh://pi@raspberrypi.local:2222" {
		t.Fatalf("unexpected target: %#v", actual)
	}
	for _, raw := range []string{"ssh://pi:password@host", "ssh://pi@host/path", "ssh://pi@host?x=y", "http://pi@host", "ssh://pi@host:0"} {
		if _, err := Parse(raw); err == nil {
			t.Fatalf("expected %q to fail", raw)
		}
	}
}

func TestParseAllowsSafeOpenSSHAliasCharacters(t *testing.T) {
	parsed, err := Parse("ssh://pi@home_pi")
	if err != nil || parsed.Host != "home_pi" {
		t.Fatalf("safe SSH alias did not parse: %#v err=%v", parsed, err)
	}
}
