BINARY := bin/bebop

.PHONY: build test test-race test-integration test-ssh-integration format check run cross

build:
	@mkdir -p bin
	go build -o $(BINARY) ./cmd/bebop

test:
	go test ./...

test-race:
	go test -race ./...

test-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^TestDebianInspect$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping integration tests."; \
	fi

test-ssh-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^TestSSHInspectAgainstDisposableDebianAndUbuntu$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping SSH integration tests."; \
	fi

format:
	gofmt -w cmd internal

check:
	@test -z "$$(gofmt -l $$(find cmd internal -name '*.go' -print))"
	go vet ./...
	go test ./...

run:
	go run ./cmd/bebop -- $(ARGS)

cross:
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/bebop-linux-amd64 ./cmd/bebop
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/bebop-linux-arm64 ./cmd/bebop
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -o bin/bebop-darwin-amd64 ./cmd/bebop
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o bin/bebop-darwin-arm64 ./cmd/bebop
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/bebop-windows-amd64.exe ./cmd/bebop
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -o bin/bebop-windows-arm64.exe ./cmd/bebop
