package resolve

import (
	"path/filepath"
	"testing"

	"github.com/bebop-home/bebop/internal/inventory"
	"github.com/bebop-home/bebop/internal/target"
)

func TestResolvePreservesLiteralCompatibilityAndResolvesInventoryAliases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bebop.hosts.toml")
	if err := inventory.WriteFile(path, inventory.Inventory{Version: inventory.CurrentVersion, Hosts: map[string]inventory.Host{
		"pi": {Target: "ssh://pi@raspberrypi.local", Config: "hosts/pi.toml"},
	}}); err != nil {
		t.Fatal(err)
	}
	alias, err := Resolve("pi", "", path)
	if err != nil {
		t.Fatal(err)
	}
	if alias.Alias != "pi" || alias.Target.Kind != target.SSH || alias.ConfigPath != filepath.Join(filepath.Dir(path), "hosts", "pi.toml") {
		t.Fatalf("unexpected alias resolution: %#v", alias)
	}
	literal, err := Resolve("", "ssh://pi@raspberrypi.local", path)
	if err != nil {
		t.Fatal(err)
	}
	if literal.Alias != "" || literal.Target.String() != "ssh://pi@raspberrypi.local" {
		t.Fatalf("unexpected literal resolution: %#v", literal)
	}
	local, err := Resolve("", "", path)
	if err != nil || local.Target.Kind != target.Local {
		t.Fatalf("unexpected local resolution: %#v err=%v", local, err)
	}
	if _, err := Resolve("pi", "ssh://pi@raspberrypi.local", path); err == nil {
		t.Fatal("expected ambiguous target rejection")
	}
}

func TestResolveAllIsAliasOrdered(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bebop.hosts.toml")
	if err := inventory.WriteFile(path, inventory.Inventory{Version: inventory.CurrentVersion, Hosts: map[string]inventory.Host{
		"z": {Target: "ssh://z@z"},
		"a": {Target: "ssh://a@a"},
	}}); err != nil {
		t.Fatal(err)
	}
	resolved, err := All(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 || resolved[0].Alias != "a" || resolved[1].Alias != "z" {
		t.Fatalf("unexpected all resolution: %#v", resolved)
	}
}
