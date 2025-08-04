#!/bin/bash

# Exit on any error
set -e

# Function to display script usage
usage() {
    echo "Usage: $0 [-f|--force]"
    echo "  -f, --force    Force cleanup without confirmation"
    exit 1
}

# Parse command line arguments
FORCE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)
            FORCE=true
            shift
            ;;
        *)
            usage
            ;;
    esac
done

# Function to check if containers are running
check_running_containers() {
    if [ "$(docker-compose ps -q)" ]; then
        return 0
    else
        return 1
    fi
}

# Function to perform cleanup
cleanup() {
    echo "🧹 Starting cleanup process..."

    # Stop and remove containers
    echo "📥 Stopping and removing containers..."
    docker-compose down -v

    # Remove unused images
    echo "🗑️ Removing unused Docker images..."
    docker image prune -f

    # Remove unused volumes
    echo "📦 Removing unused volumes..."
    docker volume prune -f

    # Remove unused networks
    echo "🌐 Removing unused networks..."
    docker network prune -f

    # Remove logs
    echo "📝 Cleaning up log files..."
    rm -f *.log

    # Remove monitoring data
    echo "📊 Cleaning up monitoring data..."
    rm -rf prometheus_data grafana_data elasticsearch_data

    echo "✅ Cleanup completed successfully!"
}

# Main execution
if check_running_containers; then
    if [ "$FORCE" = false ]; then
        echo "⚠️  Warning: This will remove all containers, volumes, and data associated with this deployment."
        read -p "Are you sure you want to proceed? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "❌ Cleanup cancelled."
            exit 1
        fi
    fi
    
    cleanup
else
    echo "ℹ️  No running containers found."
    if [ "$FORCE" = false ]; then
        read -p "Do you still want to clean up other resources? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "❌ Cleanup cancelled."
            exit 1
        fi
    fi
    
    cleanup
fi

# Final status check
if ! check_running_containers; then
    echo "🎉 All services successfully cleaned up!"
else
    echo "⚠️  Warning: Some containers might still be running. Please check 'docker-compose ps'"
fi 