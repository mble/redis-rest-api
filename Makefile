VERSION := $(shell git describe --tags --always --dirty)
BUILD := $(shell git rev-parse HEAD)
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.Build=$(BUILD) -extldflags '-static'"
MKCERT := $(shell command -v mkcert 2> /dev/null)

.PHONY: all
all: clean test build

.PHONY: test
test:
	go test -v -cover -race

.PHONY: build
build:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(PWD)/bin ./...

.PHONY: clean
clean:
	rm -f $(PWD)/bin/*

.PHONY: certs
certs:
ifdef $(MKCERT)
	openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout test-key.pem -out test-cert.pem -subj "/C=US/ST=Denial/L=Springfield/O=Dis/CN=localhost" -addext "subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1"
else
	mkcert -cert-file test-cert.pem -key-file test-key.pem localhost 127.0.0.1 ::1
endif

.PHONY: commandgen
commandgen:
	go run $(PWD)/commandgen/main.go
