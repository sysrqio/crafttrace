.PHONY: build test lint clean install

VERSION ?= 0.1.0-dev
LDFLAGS := -ldflags "-X github.com/sysrqio/crafttrace/internal/sbom.versionString=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/crafttrace ./cmd/crafttrace

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -rf bin/

install:
	go install $(LDFLAGS) ./cmd/crafttrace
