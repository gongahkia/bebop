package fleet

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
)

func TestMapPreservesInputOrderingAndIndividualFailures(t *testing.T) {
	inputs := []string{"pi", "bad", "nuc"}
	results, err := Map(context.Background(), inputs, 2, func(_ context.Context, input string) (string, error) {
		if input == "bad" {
			return "", errors.New("connection refused")
		}
		return "ok-" + input, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, input := range inputs {
		if results[index].Input != input {
			t.Fatalf("result order changed: %#v", results)
		}
	}
	if results[0].Value != "ok-pi" || results[1].Err == nil || results[2].Value != "ok-nuc" {
		t.Fatalf("individual results lost: %#v", results)
	}
}

func TestMapBoundsWorkersAndRespectsCancellation(t *testing.T) {
	inputs := []int{1, 2, 3, 4, 5}
	var active, maximum atomic.Int32
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results, err := Map(ctx, inputs, 2, func(ctx context.Context, _ int) (int, error) {
		current := active.Add(1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		active.Add(-1)
		return 1, nil
	})
	if err != nil || maximum.Load() > 2 || len(results) != len(inputs) {
		t.Fatalf("worker bound not maintained: err=%v max=%d results=%#v", err, maximum.Load(), results)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	results, err = Map(ctx, inputs, 2, func(context.Context, int) (int, error) { return 1, nil })
	if err != nil || results[0].Err == nil {
		t.Fatalf("cancelled map did not retain cancellation: err=%v results=%#v", err, results)
	}
}
