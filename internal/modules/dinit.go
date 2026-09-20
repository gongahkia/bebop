package modules

import "github.com/bebop-home/bebop/internal/transport"

// dinitEnableAndStartScript leaves Artix package-owned descriptions intact.
// dinitctl enable is the only supported persistent enablement operation: it
// uses the service's packaged enable-via/waits-for relationship rather than a
// Bebop-created boot dependency.
func dinitEnableAndStartScript(service string) string {
	description := "/etc/dinit.d/" + service
	return `set -eu
test -f ` + transport.ShellQuote(description) + `
test -d /etc/dinit.d/boot.d
dinitctl -s enable ` + transport.ShellQuote(service) + `
test -L ` + transport.ShellQuote("/etc/dinit.d/boot.d/"+service) + `
test "$(readlink -f ` + transport.ShellQuote("/etc/dinit.d/boot.d/"+service) + `)" = ` + transport.ShellQuote(description) + `
dinitctl -s start ` + transport.ShellQuote(service) + `
dinitctl -s is-started ` + transport.ShellQuote(service) + ``
}

func dinitServiceReadyScript(service string) string {
	description := "/etc/dinit.d/" + service
	return `test -f ` + transport.ShellQuote(description) + `
test -d /etc/dinit.d/boot.d
test -L ` + transport.ShellQuote("/etc/dinit.d/boot.d/"+service) + `
test "$(readlink -f ` + transport.ShellQuote("/etc/dinit.d/boot.d/"+service) + `)" = ` + transport.ShellQuote(description) + `
dinitctl -s is-started ` + transport.ShellQuote(service) + ``
}
