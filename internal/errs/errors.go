// Package errs provides errors with stable user-facing categories.
package errs

import "fmt"

// Code classifies an operational error without exposing implementation detail.
type Code string

const (
	ConfigInvalid Code = "config_invalid"
	TargetInvalid Code = "target_invalid"
	TargetUnreachable Code = "target_unreachable"
	UnsupportedOS Code = "unsupported_os"
	PrivilegeUnavailable Code = "privilege_unavailable"
	PlanBlocked Code = "plan_blocked"
	ApplyFailed Code = "apply_failed"
	VerificationFailed Code = "verification_failed"
)

// Error carries an actionable category and the underlying error where present.
type Error struct {
	Code Code
	Message string
	Err error
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
