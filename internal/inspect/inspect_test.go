package inspect

import (
	"context"
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

type storageTransport struct{ output string }

func (s storageTransport) Run(context.Context, transport.Request) (transport.Result, error) {
	return transport.Result{Stdout: s.output}, nil
}
func (storageTransport) ReadFile(context.Context, string) (string, error) { return "", nil }
func (storageTransport) FileExists(context.Context, string) (bool, error) { return false, nil }
func (storageTransport) Description() string                              { return "storage-fake" }
