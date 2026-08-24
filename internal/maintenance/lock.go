package maintenance

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/bebop-home/bebop/internal/lease"
)

var ErrJobAlreadyRunning = errors.New("maintenance job is already running")

// Locker prevents duplicate invocations of one maintenance job on one
// controller. Target-side mutation serialization remains owned by transport.
type Locker interface {
	Acquire(name string) (FileLock, error)
}

type FileLock interface {
	Release() error
}

type LocalLocker struct{ Directory string }

func (locker LocalLocker) Acquire(name string) (FileLock, error) {
	if !validLocalID(name) {
		return nil, fmt.Errorf("invalid maintenance job lock name")
	}
	return AcquireFileLock(filepath.Join(locker.Directory, name+".lock"))
}

// AcquireFileLock is retained as the M7 history/runner boundary while the
// implementation is shared with notification state. It is OS-backed on every
// supported controller and is released automatically after process death.
func AcquireFileLock(filename string) (FileLock, error) {
	handle, err := lease.Acquire(filename)
	if errors.Is(err, lease.ErrHeld) {
		return nil, ErrJobAlreadyRunning
	}
	return handle, err
}

func AcquireFileLockBlocking(filename string) (FileLock, error) {
	handle, err := lease.AcquireBlocking(filename)
	if errors.Is(err, lease.ErrHeld) {
		return nil, ErrJobAlreadyRunning
	}
	return handle, err
}
