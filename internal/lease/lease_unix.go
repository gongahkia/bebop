//go:build !windows

package lease

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

type fileLease struct{ file *os.File }

func acquire(filename string, blocking bool) (Handle, error) {
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	operation := syscall.LOCK_EX
	if !blocking {
		operation |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(file.Fd()), operation); err != nil {
		_ = file.Close()
		if !blocking && (err == syscall.EWOULDBLOCK || err == syscall.EAGAIN) {
			return nil, ErrHeld
		}
		return nil, fmt.Errorf("acquire controller-local lease: %w", err)
	}
	return fileLease{file: file}, nil
}

func (lease fileLease) Release() error {
	if lease.file == nil {
		return nil
	}
	unlockErr := syscall.Flock(int(lease.file.Fd()), syscall.LOCK_UN)
	closeErr := lease.file.Close()
	if unlockErr != nil {
		return unlockErr
	}
	return closeErr
}
