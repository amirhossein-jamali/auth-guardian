# Auth Guardian

Authentication and authorization service written in Go.

## Project Structure

- `cmd/`: Application entry points
- `internal/`: Private application code
- `tests/`: Test files
- `docker/`: Docker-related files
- `configs/`: Configuration files

## Development

### Prerequisites

- Go 1.21+
- Docker and Docker Compose (optional for containerized development)

### Getting Started

1. Clone the repository
```bash
git clone https://github.com/amirhossein-jamali/auth-guardian.git
cd auth-guardian
```

2. Install dependencies
```bash
cd new-backend
go mod download
```

3. Run tests
```bash
go test ./...
```
