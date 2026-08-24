// Package fleet runs independent read-only host operations with bounded
// concurrency while retaining the caller's deterministic input ordering.
package fleet

import (
	"context"
	"fmt"
	"sync"
)

type Result[T any, R any] struct {
	Input T
	Value R
	Err   error
}

func Map[T any, R any](ctx context.Context, inputs []T, parallel int, operation func(context.Context, T) (R, error)) ([]Result[T, R], error) {
	if parallel < 1 {
		return nil, fmt.Errorf("parallelism must be at least 1")
	}
	results := make([]Result[T, R], len(inputs))
	for index, input := range inputs {
		results[index].Input = input
	}
	if len(inputs) == 0 {
		return results, nil
	}
	if parallel > len(inputs) {
		parallel = len(inputs)
	}
	jobs := make(chan int)
	var workers sync.WaitGroup
	for worker := 0; worker < parallel; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case index, open := <-jobs:
					if !open {
						return
					}
					value, err := operation(ctx, inputs[index])
					results[index].Value = value
					results[index].Err = err
				}
			}
		}()
	}
	queued := 0
	for ; queued < len(inputs); queued++ {
		select {
		case <-ctx.Done():
			for index := queued; index < len(inputs); index++ {
				results[index].Err = ctx.Err()
			}
			close(jobs)
			workers.Wait()
			return results, nil
		case jobs <- queued:
		}
	}
	close(jobs)
	workers.Wait()
	return results, nil
}
