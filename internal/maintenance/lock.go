package maintenance

import (
	"errors"
	"fmt"
	"path/filepath"
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
