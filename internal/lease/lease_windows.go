//go:build windows

package lease

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type fileLease struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquire(filename string, blocking bool) (Handle, error) {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if !blocking {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	lease := fileLease{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &lease.overlapped); err != nil {
		_ = file.Close()
		if !blocking && err == windows.ERROR_LOCK_VIOLATION {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("acquire controller-local lease: %w", err)
	}
	return lease, nil
}

func (lease fileLease) Release() error {
	if lease.file == nil {
		return nil
	}
	unlockErr := windows.UnlockFileEx(windows.Handle(lease.file.Fd()), 0, 1, 0, &lease.overlapped)
	closeErr := lease.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
