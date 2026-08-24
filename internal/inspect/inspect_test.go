package inspect

import (
	"context"
	"strings"
	"testing"

	"github.com/bebop-home/bebop/internal/transport"
)

func TestInspectUnconfiguredStorageUsesStructuredLSBLK(t *testing.T) {
	tr := storageTransport{output: `{"blockdevices":[
  {"name":"sdb","type":"disk","size":2000,"tran":"usb","mountpoints":[null]},
  {"name":"sda","type":"disk","size":1000,"children":[{"name":"sda1","type":"part","mountpoints":["/"]}]},
  {"name":"nvme0n1","type":"disk","size":3000,"mountpoints":[null]}
]}`}
	devices := inspectUnconfiguredStorage(context.Background(), tr)
	if len(devices) != 2 || devices[0].Name != "nvme0n1" || devices[1].Name != "sdb" || devices[1].Transport != "usb" {
		t.Fatalf("unexpected storage discovery: %#v", devices)
	}
}

func TestInspectStorageNormalizesDevicesMountsAndFallback(t *testing.T) {
	tr := scriptedStorageTransport{lsblk: `{"blockdevices":[{"name":"nvme0n1","path":"/dev/nvme0n1","type":"disk","size":1000,"tran":"nvme","children":[{"name":"nvme0n1p1","path":"/dev/nvme0n1p1","type":"part","size":900,"fstype":"ext4","label":"fast","uuid":"11111111-2222-3333-4444-555555555555","mountpoints":["/mnt/fast"]}]},{"name":"sdb","path":"/dev/sdb","type":"disk","size":2000,"rm":true,"tran":"usb","mountpoints":[null]}]}`, findmnt: `{"filesystems":[{"target":"/","source":"/dev/root","fstype":"ext4","options":"rw","size":500,"avail":200},{"target":"/mnt/fast","source":"/dev/nvme0n1p1","fstype":"ext4","options":"rw,noatime","size":900,"avail":600}]}`}
	storage := inspectStorage(context.Background(), tr)
	if !storage.Available || len(storage.Devices) != 3 || len(storage.Mounts) != 2 {
		t.Fatalf("unexpected normalized storage: %#v", storage)
	}
	if storage.Mounts[1].UUID != "11111111-2222-3333-4444-555555555555" || storage.Mounts[1].AvailableBytes != 600 {
		t.Fatalf("mount identity/capacity was not joined: %#v", storage.Mounts[1])
	}
	tr.findmnt = ""
	fallback := inspectStorage(context.Background(), tr)
	if !fallback.Available || len(fallback.Mounts) != 1 || fallback.Mounts[0].Target != "/mnt/fast" || fallback.Mounts[0].UUID == "" {
		t.Fatalf("lsblk fallback was not safe/useful: %#v", fallback)
	}
	tr.lsblk, tr.findmnt = "not-json", `{"filesystems":[{"target":"/mnt/fast","source":"/dev/nvme0n1p1","fstype":"ext4","options":"rw","size":900,"avail":600}]}`
	findmntOnly := inspectStorage(context.Background(), tr)
	if !findmntOnly.Available || len(findmntOnly.Devices) != 0 || len(findmntOnly.Mounts) != 1 || findmntOnly.Mounts[0].UUID != "" || findmntOnly.Mounts[0].AvailableBytes != 600 {
		t.Fatalf("findmnt-only fallback was not safely normalized: %#v", findmntOnly)
	}
}

type storageTransport struct{ output string }

func (s storageTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	return transport.Result{Stdout: s.output}, nil
}
func (storageTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (storageTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (storageTransport) Description() string                              { return "storage-fake" }

type scriptedStorageTransport struct{ lsblk, findmnt string }

func (s scriptedStorageTransport) Run(_ context.Context, request transport.Request) (transport.Result, error) {
	if strings.Contains(request.Script, "findmnt --json") {
		return transport.Result{Stdout: s.findmnt}, nil
	}
	return transport.Result{Stdout: s.lsblk}, nil
}
func (scriptedStorageTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (scriptedStorageTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (scriptedStorageTransport) Description() string                              { return "scripted-storage-fake" }
