VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse HEAD)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all
all: check build

.PHONY: check
check: format-check test vet lint

.PHONY: test
test:
	go test -race -cover ./...

.PHONY: integration
integration:
	test -n "$(TEST_REDIS_URL)"
	go test -race -v ./integration

.PHONY: bench
bench:
	go test -run '^$$' -bench . -benchmem ./internal/httpapi ./internal/token

.PHONY: vet
vet:
	go vet ./...

.PHONY: lint
lint:
	golangci-lint run

.PHONY: format
format:
	gofmt -w ./cmd ./integration ./internal

.PHONY: format-check
format-check:
	test -z "$$(gofmt -l ./cmd ./integration ./internal)"

.PHONY: build
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/redis-rest-api ./cmd/redis-rest-api
	CGO_ENABLED=0 go build -trimpath -o bin/token-gen ./cmd/token-gen

.PHONY: clean
clean:
	rm -f bin/redis-rest-api bin/token-gen coverage.out
