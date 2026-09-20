// Package buildinfo provides the controller version used by persistent plan
// artifacts. Releases can replace this constant through the normal build flow.
package buildinfo

// Version has a development default. Release builds replace it with the exact
// validated tag through -ldflags; persistent artifacts then record the version
// of the controller that created them without maintaining a second version
// source in the repository.
var Version = "0.2.0"
