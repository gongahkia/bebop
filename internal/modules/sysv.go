package modules

import "github.com/bebop-home/bebop/internal/transport"

// sysvEnableAndStartScript relies on the package-provided init script and
// update-rc.d policy. It deliberately never creates runlevel links itself.
func sysvEnableAndStartScript(service string) string {
	initScript := "/etc/init.d/" + service
	return `set -eu
test -x ` + transport.ShellQuote(initScript) + `
update-rc.d ` + transport.ShellQuote(service) + ` defaults
enabled=no
for link in /etc/rc[2345].d/S??` + service + `; do
  test -L "$link" && test "$(readlink -f "$link")" = ` + transport.ShellQuote(initScript) + ` || continue
  enabled=yes
  break
done
test "$enabled" = yes
service ` + transport.ShellQuote(service) + ` start`
}

func sysvServiceReadyScript(service string) string {
	initScript := "/etc/init.d/" + service
	return `test -x ` + transport.ShellQuote(initScript) + `
enabled=no
for link in /etc/rc[2345].d/S??` + service + `; do
  test -L "$link" && test "$(readlink -f "$link")" = ` + transport.ShellQuote(initScript) + ` || continue
  enabled=yes
  break
done
test "$enabled" = yes
service ` + transport.ShellQuote(service) + ` status >/dev/null 2>&1`
}
