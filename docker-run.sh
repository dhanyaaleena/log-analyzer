#!/bin/bash

# Log Analyzer Docker Setup Script
# This script runs the log analyzer application locally using Docker

set -e

echo "🚀 Starting Log Analyzer with Docker..."

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Build and start the services
print_status "Building and starting services..."
docker-compose up --build -d

# Wait for services to be ready
print_status "Waiting for services to be ready..."
sleep 10

# Check service status
print_status "Checking service status..."
docker-compose ps

# Show logs
print_status "Showing logs (Ctrl+C to stop viewing logs)..."
docker-compose logs -f

echo ""
echo "✅ Log Analyzer is now running!"
echo "🌐 Frontend: http://localhost:3001"
echo "🔧 Backend API: http://localhost:5001"
echo "🗄️ PostgreSQL: localhost:5433"
echo ""
echo "📝 Useful commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop services: docker-compose down"
echo "  - Restart services: docker-compose restart"
echo "  - Rebuild: docker-compose up --build"
echo "  - Access PostgreSQL: docker-compose exec postgres psql -U dbuser -d loganalyzerdb" 