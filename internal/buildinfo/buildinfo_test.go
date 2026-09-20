package buildinfo

import "testing"

func TestVersionHasDevelopmentDefault(t *testing.T) {
	if Version == "" {
		t.Fatal("controller version must have a development default")
	}
}
