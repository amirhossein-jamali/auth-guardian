#!/bin/bash

# Navigate to the docker directory
cd "$(dirname "$0")"

# Stop and remove existing containers if they exist
docker-compose down

# Build and start containers
docker-compose up -d

echo "Starting services..."
sleep 5

# Show logs
echo "Showing logs (press Ctrl+C to exit):"
docker-compose logs -f 