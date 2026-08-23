// Package plan defines Bebop's immutable, serializable change model.
package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type Risk string

const (
	Safe             Risk = "safe"
	Privileged       Risk = "privileged"
	NetworkSensitive Risk = "network-sensitive"
	Destructive      Risk = "destructive"
)

type Action struct {
	Kind     string `json:"kind"`
	Resource string `json:"resource,omitempty"`
	Script   string `json:"script"`
}

// Change is both reviewable plan data and the sole executable input to apply.
// Scripts contain only static module templates plus shell-quoted validated data.
type Change struct {
	ID           string   `json:"id"`
	Module       string   `json:"module"`
	Summary      string   `json:"summary"`
	Reason       string   `json:"reason"`
	Risk         Risk     `json:"risk"`
	RequiresRoot bool     `json:"requires_root"`
	Current      string   `json:"current"`
	Desired      string   `json:"desired"`
	Dependencies []string `json:"dependencies,omitempty"`
	Action       Action   `json:"action"`
	Verification string   `json:"verification"`
	Blocked      string   `json:"blocked,omitempty"`
}

type Warning struct {
	ID         string `json:"id"`
	Module     string `json:"module"`
	Summary    string `json:"summary"`
	Resolution string `json:"resolution,omitempty"`
}

type Plan struct {
	Version     int       `json:"version"`
	Target      string    `json:"target"`
	Changes     []Change  `json:"changes"`
	Warnings    []Warning `json:"warnings"`
	Fingerprint string    `json:"fingerprint"`
}

type canonicalPlan struct {
	Version  int       `json:"version"`
	Target   string    `json:"target"`
	Changes  []Change  `json:"changes"`
	Warnings []Warning `json:"warnings"`
}

func (p Plan) CanonicalJSON() ([]byte, error) {
	return json.Marshal(canonicalPlan{Version: p.Version, Target: p.Target, Changes: p.Changes, Warnings: p.Warnings})
}

func (p *Plan) Finalize() error {
	if err := SortChanges(p.Changes); err != nil {
		return err
	}
	sort.Slice(p.Warnings, func(i, j int) bool { return p.Warnings[i].ID < p.Warnings[j].ID })
	bytes, err := p.CanonicalJSON()
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bytes)
	p.Fingerprint = hex.EncodeToString(sum[:])
	return nil
}

// SortChanges performs lexical Kahn topological sorting. IDs are the stable
// tie-breaker, so neither module registration nor map iteration affects a plan.
func SortChanges(changes []Change) error {
	byID := make(map[string]int, len(changes))
	for index, change := range changes {
		if change.ID == "" {
			return fmt.Errorf("plan contains an empty change ID")
		}
		if _, exists := byID[change.ID]; exists {
			return fmt.Errorf("plan contains duplicate change ID %q", change.ID)
		}
		byID[change.ID] = index
	}
	inDegree := make(map[string]int, len(changes))
	next := make(map[string][]string, len(changes))
	for _, change := range changes {
		for _, dependency := range change.Dependencies {
			if _, exists := byID[dependency]; !exists {
				return fmt.Errorf("change %q depends on absent change %q", change.ID, dependency)
			}
			inDegree[change.ID]++
			next[dependency] = append(next[dependency], change.ID)
		}
	}
	ready := make([]string, 0, len(changes))
	for _, change := range changes {
		if inDegree[change.ID] == 0 {
			ready = append(ready, change.ID)
		}
	}
	sort.Strings(ready)
	ordered := make([]Change, 0, len(changes))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		ordered = append(ordered, changes[byID[id]])
		for _, child := range next[id] {
			inDegree[child]--
			if inDegree[child] == 0 {
				ready = append(ready, child)
			}
		}
		sort.Strings(ready)
	}
	if len(ordered) != len(changes) {
		return fmt.Errorf("change dependency cycle detected")
	}
	copy(changes, ordered)
	return nil
}
