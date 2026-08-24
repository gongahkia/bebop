BINARY := bin/bebop

.PHONY: build test test-race test-integration test-ssh-integration test-compose-integration test-backup-integration test-migration-integration test-recipe-integration test-storage test-storage-integration test-maintenance test-maintenance-integration recipe-validate format check run cross

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

test-compose-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^TestComposeLifecycleAgainstDisposableDind$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping Compose integration tests."; \
	fi

test-backup-integration test-migration-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^TestBackupRestoreMigrationAgainstDisposableDind$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping backup/migration integration tests."; \
	fi

test-recipe-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^TestRecipe(MaterializeApplyAndNoop|StatefulBackupRestore)AgainstDisposableDind$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping recipe integration tests."; \
	fi

test-storage:
	go test ./internal/storage ./internal/modules ./internal/config ./internal/services

test-storage-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^Test(ManagedStorageMountAgainstDisposableImage|StoragePlacementMigrationAgainstDisposableDind)$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping storage integration tests."; \
	fi

test-maintenance:
	go test ./internal/maintenance ./internal/backup ./internal/config ./internal/cli

test-maintenance-integration:
	@if docker info >/dev/null 2>&1; then \
		BEBOP_INTEGRATION_DOCKER=1 go test -tags=integration -run '^TestMaintenanceBackupRetentionAgainstDisposableDind$$' ./internal/integration; \
	else \
		echo "Docker daemon unavailable; skipping maintenance integration tests."; \
	fi

recipe-validate:
	go run ./cmd/bebop recipe validate

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
