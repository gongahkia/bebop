// Package target parses the explicit machine targets accepted by Bebop.
package target

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/bebop-home/bebop/internal/errs"
)

type Kind string

const (
	Local Kind = "local"
	SSH Kind = "ssh"
)

// Target contains only fields that are safe to pass as process arguments.
type Target struct {
	Kind Kind
	User string
	Host string
	Port int
}

var userPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)
var hostPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]*$`)

func Parse(raw string) (Target, error) {
	if raw == "" || raw == "local" {
		return Target{Kind: Local}, nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Target{}, errs.New(errs.TargetInvalid, "invalid target", err)
	}
	if u.Scheme != "ssh" || u.Host == "" || u.User == nil || u.User.Username() == "" {
		return Target{}, errs.New(errs.TargetInvalid, "target must be local or ssh://user@host[:port]", nil)
	}
	_, hasPassword := u.User.Password()
	if hasPassword || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return Target{}, errs.New(errs.TargetInvalid, "SSH targets cannot include passwords, paths, queries, or fragments", nil)
	}
	user := u.User.Username()
	host := u.Hostname()
	if !userPattern.MatchString(user) {
		return Target{}, errs.New(errs.TargetInvalid, "SSH user contains unsupported characters", nil)
	}
	if net.ParseIP(host) == nil && !hostPattern.MatchString(host) {
		return Target{}, errs.New(errs.TargetInvalid, "SSH host contains unsupported characters", nil)
	}
	port := 0
	if rawPort := u.Port(); rawPort != "" {
		port, err = strconv.Atoi(rawPort)
		if err != nil || port < 1 || port > 65535 {
			return Target{}, errs.New(errs.TargetInvalid, "SSH port must be between 1 and 65535", nil)
		}
	}
	return Target{Kind: SSH, User: user, Host: host, Port: port}, nil
}

func (t Target) String() string {
	if t.Kind == Local {
		return "local"
	}
	host := t.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if t.Port != 0 {
		return fmt.Sprintf("ssh://%s@%s:%d", t.User, host, t.Port)
	}
	return fmt.Sprintf("ssh://%s@%s", t.User, host)
}
