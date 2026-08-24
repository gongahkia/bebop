// Package lease provides tiny crash-safe controller-local advisory leases.
// Files can remain after a process exits; ownership is the OS-held lock, never
// the presence of a pathname.
package lease

import "errors"

var ErrHeld = errors.New("controller-local lease is already held")

type Handle interface {
	Release() error
}

// Acquire obtains a non-blocking exclusive lease. The kernel releases it if
// the process exits or crashes.
func Acquire(filename string) (Handle, error) { return acquire(filename, false) }

// AcquireBlocking obtains an exclusive lease, waiting only for short local
// history/state writes. Long-running maintenance jobs use Acquire.
func AcquireBlocking(filename string) (Handle, error) { return acquire(filename, true) }
