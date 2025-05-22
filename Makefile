.PHONY: all build test clean docker-build docker-up docker-down lint

all: test build

# Build the application
build:
	@echo "Building auth-guardian..."
	go build -o bin/auth-guardian ./cmd/api

# Run tests
test:
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...

# Run tests with coverage report
test-coverage: test
	go tool cover -html=coverage.txt

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	rm -rf bin/
	rm -f coverage.txt

# Run linter
lint:
	@echo "Running linter..."
	golangci-lint run

# Docker commands
docker-build:
	@echo "Building Docker containers..."
	docker-compose -f docker/docker-compose.yml build

docker-up:
	@echo "Starting Docker containers..."
	docker-compose -f docker/docker-compose.yml up -d

docker-down:
	@echo "Stopping Docker containers..."
	docker-compose -f docker/docker-compose.yml down

# Run all tests in Docker environment
docker-test:
	@echo "Running tests in Docker..."
	docker-compose -f docker/docker-compose.yml run --rm api go test -v ./...

# Full CI pipeline locally
ci: lint test docker-build docker-up docker-test docker-down
	@echo "CI pipeline completed successfully" 