//go:build !windows

package transport

import "os"

func requiresLocalSudo() bool { return os.Geteuid() != 0 }
