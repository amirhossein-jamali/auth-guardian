# Build stage
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o main ./cmd/api

# Run stage
FROM alpine:latest

# Install curl for healthchecks
RUN apk --no-cache add curl ca-certificates

# Create app directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/main .
COPY --from=builder /app/configs ./configs

# Create a directory for logs
RUN mkdir -p /app/logs && chmod -R 777 /app/logs

# Ensure configs are readable
RUN chmod -R 755 /app/configs

# Expose port
EXPOSE 8080

# Set environment variable for config path
ENV CONFIG_PATH=/app/configs/

# Command to run the executable
CMD ["./main"]

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/health || exit 1