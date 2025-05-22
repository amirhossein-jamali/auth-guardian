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
RUN apk --no-cache add curl ca-certificates tzdata

# Create app directory
WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/main .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Create a directory for logs
RUN mkdir -p /app/logs && chmod -R 777 /app/logs

# Ensure configs are readable
RUN chmod -R 755 /app/configs

# Create entrypoint script
RUN echo '#!/bin/sh' > /app/entrypoint.sh && \
    echo 'echo "Database host: $AUTH_GUARDIAN_DB_HOST"' >> /app/entrypoint.sh && \
    echo './main' >> /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Expose port
EXPOSE 8080

# Set environment variables for config path, but don't hardcode ENV
ENV CONFIG_PATH=/app/configs/

# Command to run the executable
CMD ["/app/entrypoint.sh"]

# Healthcheck - modified for working behind reverse proxy
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 CMD curl -f http://localhost:8080/health -H "X-Forwarded-Proto: https" || exit 1