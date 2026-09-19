package modules

import "github.com/bebop-home/bebop/internal/transport"

// runitEnableAndStartScript takes ownership only of the exact service link.
// It refuses a non-symlink or differently-targeted link instead of replacing
// it, and never edits the package-owned /etc/sv service definition.
func runitEnableAndStartScript(service string) string {
	directory := "/etc/sv/" + service
	link := "/var/service/" + service
	return `set -eu
test -L /var/service
test -d /var/service
test "$(readlink -f /var/service)" = /run/runit/runsvdir/current
test -d ` + transport.ShellQuote(directory) + `
test ! -L ` + transport.ShellQuote(directory) + `
if test -L ` + transport.ShellQuote(link) + `; then
  test "$(readlink -f ` + transport.ShellQuote(link) + `)" = "$(readlink -f ` + transport.ShellQuote(directory) + `)"
elif test -e ` + transport.ShellQuote(link) + `; then
  exit 1
else
  ln -s ` + transport.ShellQuote(directory) + ` ` + transport.ShellQuote(link) + `
fi
test -L ` + transport.ShellQuote(link) + `
test "$(readlink -f ` + transport.ShellQuote(link) + `)" = "$(readlink -f ` + transport.ShellQuote(directory) + `)"
sv up ` + transport.ShellQuote(service)
}

func runitServiceReadyScript(service string) string {
	return `test -d ` + transport.ShellQuote("/etc/sv/"+service) + `
test ! -L ` + transport.ShellQuote("/etc/sv/"+service) + `
test -L /var/service
test "$(readlink -f /var/service)" = /run/runit/runsvdir/current
test -L ` + transport.ShellQuote("/var/service/"+service) + `
test "$(readlink -f ` + transport.ShellQuote("/var/service/"+service) + `)" = "$(readlink -f ` + transport.ShellQuote("/etc/sv/"+service) + `)"
sv status ` + transport.ShellQuote(service) + ` | grep -Eq '^run:'`
}
