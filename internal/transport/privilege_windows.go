//go:build windows

package transport

// Windows is a supported controller build target for remote SSH workflows, not
// a Bebop convergence target. Any attempted privileged local execution follows
// the existing sudo path and fails safely rather than compiling in Unix APIs.
func requiresLocalSudo() bool { return true }
