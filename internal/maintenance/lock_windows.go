//go:build windows

package maintenance

import "fmt"

// M7 has no Windows scheduler adapter. Refusing unattended local execution
// without a crash-safe cross-process lease is safer than a stale lockfile.
func AcquireFileLock(string) (FileLock, error) {
	return nil, fmt.Errorf("maintenance local job locking is unavailable on Windows controllers")
}

func AcquireFileLockBlocking(string) (FileLock, error) {
	return nil, fmt.Errorf("maintenance local job locking is unavailable on Windows controllers")
}
