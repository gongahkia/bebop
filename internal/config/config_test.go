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

func TestPersistentDataDeclarationsAreExplicitAndSafe(t *testing.T) {
	actual, err := Decode(strings.NewReader(`version = 1

[backup]
destination = ".bebop/backups"

[services.hello]
type = "compose"
source = "services/hello"

[[services.hello.data]]
name = "app-data"
type = "volume"
volume = "data"

[[services.hello.data]]
name = "uploads"
type = "path"
path = "/srv/hello/uploads"

[services.hello.backup]
consistency = "live"
`))
	if err != nil {
		t.Fatal(err)
	}
	if actual.Backup.Destination != ".bebop/backups" || len(actual.Services[0].Data) != 2 || actual.Services[0].Backup.Consistency != "live" {
		t.Fatalf("persistent data declarations did not decode: %#v", actual)
	}
	for _, contents := range []string{
		"version = 1\n[backup]\ndestination = '../escape'\n",
		"version = 1\n[services.hello]\ntype='compose'\nsource='services/hello'\n[[services.hello.data]]\nname='data'\ntype='volume'\nvolume='../bad'\n",
		"version = 1\n[services.hello]\ntype='compose'\nsource='services/hello'\n[[services.hello.data]]\nname='data'\ntype='path'\npath='/etc'\n",
		"version = 1\n[services.hello]\ntype='compose'\nsource='services/hello'\n[[services.hello.data]]\nname='data'\ntype='path'\npath='/srv/bebop/services/hello'\n",
		"version = 1\n[services.hello]\ntype='compose'\nsource='services/hello'\n[services.hello.backup]\nconsistency='hook'\n",
	} {
		if _, err := Decode(strings.NewReader(contents)); err == nil {
			t.Fatalf("expected unsafe persistent-data declaration to fail: %s", contents)
		}
	}
}

func TestStorageResourcesAndRelativePersistentPaths(t *testing.T) {
	cfg, err := Decode(strings.NewReader(`version = 1

[storage.resources.bulk]
mount = "/mnt/bulk"
filesystem_uuid = "11111111-2222-3333-4444-555555555555"
filesystem_type = "ext4"
minimum_capacity_bytes = 100
minimum_free_bytes = 10
managed_mount = true

[services.hello]
type = "compose"
source = "services/hello"

[[services.hello.data]]
name = "media"
type = "path"
storage = "bulk"
path = "media"
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Storage.Resources) != 1 || cfg.Storage.Resources[0].Name != "bulk" || cfg.Services[0].Data[0].Storage != "bulk" {
		t.Fatalf("storage declaration did not decode: %#v", cfg)
	}
	resolved, err := ResolveDataPath(cfg.Storage, cfg.Services[0].Data[0])
	if err != nil || resolved != "/mnt/bulk/media" {
		t.Fatalf("relative placement = %q, %v", resolved, err)
	}
	for _, contents := range []string{
		"version=1\n[storage.resources.bulk]\nmount='/'\nfilesystem_uuid='11111111-2222-3333-4444-555555555555'\n",
		"version=1\n[storage.resources.bulk]\nmount='/mnt/bulk'\nfilesystem_uuid='11111111-2222-3333-4444-555555555555'\n[storage.resources.other]\nmount='/mnt/bulk/child'\nfilesystem_uuid='22222222-2222-3333-4444-555555555555'\n",
		"version=1\n[services.hello]\ntype='compose'\nsource='services/hello'\n[[services.hello.data]]\nname='media'\ntype='path'\nstorage='bulk'\npath='../escape'\n",
	} {
		if _, err := Decode(strings.NewReader(contents)); err == nil {
			t.Fatalf("unsafe storage declaration was accepted: %s", contents)
		}
	}
}

func TestParseByteSizeAndStorageHumanCapacity(t *testing.T) {
	for value, want := range map[string]int64{"20GiB": 20 << 30, "500MiB": 500 << 20, "1TiB": 1 << 40, "1GB": 1000 * 1000 * 1000} {
		got, err := ParseByteSize(value)
		if err != nil || got != want {
			t.Fatalf("ParseByteSize(%q) = %d, %v; want %d", value, got, err, want)
		}
	}
	for _, value := range []string{"20", "-1GiB", "1XB", "999999999999999999999TiB"} {
		if _, err := ParseByteSize(value); err == nil {
			t.Fatalf("ParseByteSize accepted %q", value)
		}
	}
	cfg, err := Decode(strings.NewReader("version = 1\n[storage.resources.bulk]\nmount='/mnt/bulk'\nfilesystem_uuid='11111111-2222-3333-4444-555555555555'\nminimum_capacity='1TiB'\nminimum_free='20GiB'\n"))
	if err != nil || cfg.Storage.Resources[0].MinimumCapacityBytes != 1<<40 || cfg.Storage.Resources[0].MinimumFreeBytes != 20<<30 {
		t.Fatalf("human capacities did not normalize: %#v %v", cfg.Storage.Resources, err)
	}
}
