package plan

import "testing"

func TestSortChangesDeterministicAndCycles(t *testing.T) {
	changes := []Change{{ID: "z"}, {ID: "b", Dependencies: []string{"a"}}, {ID: "a"}, {ID: "c", Dependencies: []string{"a"}}}
	if err := SortChanges(changes); err != nil {
		t.Fatal(err)
	}
	got := []string{changes[0].ID, changes[1].ID, changes[2].ID, changes[3].ID}
	expected := []string{"a", "b", "c", "z"}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("order %#v", got)
		}
	}
	if err := SortChanges([]Change{{ID: "a", Dependencies: []string{"b"}}, {ID: "b", Dependencies: []string{"a"}}}); err == nil {
		t.Fatal("expected cycle failure")
	}
}
