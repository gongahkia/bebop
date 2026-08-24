// Package errs provides errors with stable user-facing categories.
package errs

import "fmt"

// Code classifies an operational error without exposing implementation detail.
type Code string

const (
	ConfigInvalid          Code = "config_invalid"
	InventoryInvalid       Code = "inventory_invalid"
	TargetInvalid          Code = "target_invalid"
	TargetUnreachable      Code = "target_unreachable"
	TargetAuthentication   Code = "target_authentication"
	TargetHostKey          Code = "target_host_key"
	TargetTimeout          Code = "target_timeout"
	UnsupportedOS          Code = "unsupported_os"
	PrivilegeUnavailable   Code = "privilege_unavailable"
	PlanBlocked            Code = "plan_blocked"
	PlanInvalid            Code = "plan_invalid"
	PlanTampered           Code = "plan_tampered"
	PlanStale              Code = "plan_stale"
	TargetIdentityMismatch Code = "target_identity_mismatch"
	ApplyLocked            Code = "apply_locked"
	ApplyFailed            Code = "apply_failed"
	VerificationFailed     Code = "verification_failed"
	MultiHostFailed        Code = "multi_host_failed"
)

// Error carries an actionable category and the underlying error where present.
type Error struct {
	Code    Code
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

func New(code Code, message string, err error) *Error {
	return &Error{Code: code, Message: message, Err: err}
}
