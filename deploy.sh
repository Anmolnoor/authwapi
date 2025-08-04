#!/bin/bash

# Exit on any error
set -e

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | awk '/=/ {print $1}')
fi

# Function to validate required environment variables
check_required_vars() {
    local required_vars=(
        "DATABASE_URL"
        "JWT_SECRET"
        "PORT"
        "AWS_ACCESS_KEY_ID"
        "AWS_SERECT_ACCESS_KEY"
        "AWS_REGION"
        "AWS_BUCKET_NAME"
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
echo "🚀 Deploying AuthAPI..."

# Pull latest changes if in git repository
# if [ -d .git ]; then
#     echo "📥 Pulling latest changes..."
#     git pull
# fi

# Build and start containers
echo "🏗️ Building and starting containers..."
docker-compose down
docker-compose build --no-cache
docker-compose up -d

# Get container ID
CONTAINER_ID=$(docker-compose ps -q auth-api)

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
    docker-compose logs auth-api
    exit 1
fi

# Show logs
echo "📝 Recent logs:"
docker-compose logs --tail=50 auth-api 

# Monitor deployment health
monitor_health() {
    local retry_count=0
    local max_retries=5

    while [ $retry_count -lt $max_retries ]; do
        if curl -s "http://localhost:${PORT}/health" > /dev/null; then
            echo "✅ Service is healthy"
            return 0
        fi
        echo "Waiting for service to become healthy..."
        sleep 5
        retry_count=$((retry_count + 1))
    done

    echo "❌ Service failed health check"
    return 1
}

# Add after deployment
monitor_health