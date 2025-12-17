#!/usr/bin/env bash

# Strict mode
set -euo pipefail

# Use docker compose v2 if available, fallback to docker-compose
compose() {
  if command -v docker &>/dev/null && docker compose version &>/dev/null; then
    docker compose "$@"
  else
    docker-compose "$@"
  fi
}

# Load environment variables if .env exists
if [ -f .env ]; then
  # shellcheck disable=SC2046
  export $(grep -v '^#' .env | xargs -0 || true)
fi

# Function to validate required environment variables
check_required_vars() {
    local required_vars=(
        "DATABASE_URL"
        "JWT_SECRET"
        "PORT"
    )

    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            echo "Error: Required environment variable $var is not set"
            exit 1
        fi
    done
}

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Error: Docker is not running"
    exit 1
fi

# Validate environment variables
check_required_vars

# Build and deploy
echo "🚀 Deploying AuthWAPI..."

# Pull latest changes if in git repository
# if [ -d .git ]; then
#     echo "📥 Pulling latest changes..."
#     git pull
# fi

# Build and start containers
echo "🏗️ Building and starting containers..."
compose down --remove-orphans
compose build --no-cache
compose up -d

# Get container ID
CONTAINER_ID=$(compose ps -q auth-api)

# Get container IP
CONTAINER_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER_ID)

# Check if deployment was successful
if [ "$(docker inspect -f {{.State.Running}} $CONTAINER_ID)" = "true" ]; then
    echo "✅ Deployment successful!"
    echo "📊 Deployment Information:"
    echo "Container ID: $CONTAINER_ID"
    echo "Container IP: $CONTAINER_IP"
    echo "Port: $PORT"
    echo "Status: Running"
else
    echo "❌ Deployment failed!"
    compose logs auth-api
    exit 1
fi

# Show logs
echo "📝 Recent logs:"
compose logs --tail=50 auth-api 

# Monitor deployment health
monitor_health() {
    local retry_count=0
    local max_retries=10

    while [ $retry_count -lt $max_retries ]; do
        if curl -sf "http://localhost:${PORT}/health" > /dev/null; then
            echo "✅ Service is healthy"
            return 0
        fi
        echo "Waiting for service to become healthy... (${retry_count}/${max_retries})"
        sleep 5
        retry_count=$((retry_count + 1))
    done

    echo "❌ Service failed health check"
    return 1
}

# Add after deployment
monitor_health