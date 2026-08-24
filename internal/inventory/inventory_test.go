package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCanonicalTOMLIsStableAndRoundTrips(t *testing.T) {
	input := Inventory{Version: CurrentVersion, Hosts: map[string]Host{
		"nuc": {Target: "ssh://admin@nuc.local", Config: "hosts/nuc.toml"},
		"pi":  {Target: "ssh://pi@raspberrypi.local", Config: "hosts/pi.toml"},
	}}
	first, err := input.CanonicalTOML()
	if err != nil {
		t.Fatal(err)
	}
	second, err := input.CanonicalTOML()
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) || !strings.Contains(string(first), "[hosts.nuc]") || strings.Index(string(first), "[hosts.nuc]") > strings.Index(string(first), "[hosts.pi]") {
		t.Fatalf("inventory was not canonical:\n%s", first)
	}
	roundTripped, err := Decode(strings.NewReader(string(first)))
	if err != nil {
		t.Fatal(err)
	}
	if roundTripped.Hosts["pi"].Config != "hosts/pi.toml" || roundTripped.Hosts["nuc"].Target != "ssh://admin@nuc.local" {
		t.Fatalf("unexpected round trip: %#v", roundTripped)
	}
}

func TestInventoryValidationRejectsUnsafeOrAmbiguousValues(t *testing.T) {
	for _, contents := range []string{
		"version = 2\n",
		"version = 1\n[hosts.local]\ntarget = \"ssh://pi@home\"\n",
		"version = 1\n[hosts.pi]\ntarget = \"ssh://pi@home\"\nconfig = \"../outside.toml\"\n",
		"version = 1\n[hosts.pi]\ntarget = \"ssh://pi@home\"\nunknown = true\n",
		"version = 1\n[hosts.pi]\ntarget = \"ssh://pi@home\"\n[hosts.nuc]\ntarget = \"ssh://pi@home\"\n",
	} {
		if _, err := Decode(strings.NewReader(contents)); err == nil {
			t.Fatalf("expected inventory rejection for:\n%s", contents)
		}
	}
}

func TestWriteAddAndRemoveAreAtomicAndScopedToInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "bebop.hosts.toml")
	result, err := LoadOrEmpty(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := result.Add("pi", Host{Target: "ssh://pi@home", Config: "hosts/pi.toml"}); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, result); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, result); err != nil {
		t.Fatal(err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("repeated inventory write changed bytes:\n%s\n%s", first, second)
	}
	if err := result.Add("pi", Host{Target: "ssh://other@home"}); err == nil {
		t.Fatalf("expected duplicate alias rejection")
	}
	if err := result.Remove("pi"); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, result); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Hosts) != 0 {
		t.Fatalf("remove left hosts: %#v", loaded.Hosts)
	}
}

func TestConfigPathResolvesOnlyWithinInventoryDirectory(t *testing.T) {
	path := filepath.Join("project", "bebop.hosts.toml")
	if got, want := ConfigPath(path, Host{Config: "hosts/pi.toml"}), filepath.Join("project", "hosts", "pi.toml"); got != want {
		t.Fatalf("config path = %q, want %q", got, want)
	}
}

func TestAddRejectsControlCharactersBeforeCanonicalSerialization(t *testing.T) {
	result := Empty()
	if err := result.Add("pi", Host{Target: "ssh://pi@home", Config: "hosts/pi\n.toml"}); err == nil {
		t.Fatal("control character in controller path was accepted")
	}
}
