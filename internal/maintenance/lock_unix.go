//go:build !windows

package maintenance

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type advisoryFileLock struct{ file *os.File }

// AcquireFileLock uses a process-held advisory flock. A stale lock file is
// harmless because the kernel releases the lock if a scheduler/manual process
// exits or crashes.
func AcquireFileLock(filename string) (FileLock, error) {
	return acquireFileLock(filename, syscall.LOCK_EX|syscall.LOCK_NB)
}

func AcquireFileLockBlocking(filename string) (FileLock, error) {
	return acquireFileLock(filename, syscall.LOCK_EX)
}

func acquireFileLock(filename string, operation int) (FileLock, error) {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		_ = file.Close()
		if operation&syscall.LOCK_NB != 0 && (err == syscall.EWOULDBLOCK || err == syscall.EAGAIN) {
			return nil, ErrJobAlreadyRunning
		}
		return nil, fmt.Errorf("maintenance job is already running")
	}
	return advisoryFileLock{file: file}, nil
}

func (lock advisoryFileLock) Release() error {
	if lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
