// Package modules provides Bebop M0's deliberately small capability set.
package modules

import "github.com/bebop-home/bebop/internal/module"

func Default() []module.Module {
	return []module.Module{Base{}, Updates{}, Docker{}, Tailscale{}, SSH{}}
}
