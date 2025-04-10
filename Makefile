# Makefile for asmauthextension

.PHONY: build test clean tidy

# Default target
all: build

# Build the extension
build:
	go build ./...

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-with-cover:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -f coverage.out coverage.html

# Tidy go modules
tidy:
	go mod tidy

# Download dependencies
deps:
	go mod download

# Generate metadata files
generate:
	go run go.opentelemetry.io/collector/cmd/mdatagen ./metadata.yaml
