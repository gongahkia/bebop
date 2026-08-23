package transport

import "strings"

// ShellQuote returns a POSIX-shell single-quoted literal. It is intentionally
// small and used for validated configuration values and fixed target paths.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
