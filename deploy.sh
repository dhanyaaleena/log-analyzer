#!/bin/bash

# Log Analyzer Deployment Script
# This script deploys both backend and frontend from a cloned repository

set -e

echo "🚀 Starting Log Analyzer Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root"
   exit 1
fi

# Store the original working directory (where the script is run from)
ORIGINAL_DIR="$(pwd)"

# Set deployment paths
BACKEND_PATH="/var/www/log-analyzer/backend"
FRONTEND_PATH="/var/www/log-analyzer/frontend"
FRONTEND_BUILD_PATH="/var/www/log-analyzer-frontend"

print_status "Setting up deployment paths..."
print_status "Original directory: $ORIGINAL_DIR"

# Create directories if they don't exist
sudo mkdir -p $BACKEND_PATH
sudo mkdir -p $FRONTEND_BUILD_PATH
sudo mkdir -p /var/log/gunicorn

# Set proper permissions
sudo chown -R www-data:www-data $BACKEND_PATH
sudo chown -R www-data:www-data $FRONTEND_BUILD_PATH
sudo chown -R www-data:www-data /var/log/gunicorn

print_status "Deploying Backend..."

# Copy backend files from current directory
sudo cp -r backend/* $BACKEND_PATH/

# Create virtual environment if it doesn't exist
if [ ! -d "$BACKEND_PATH/venv" ]; then
    print_status "Creating Python virtual environment..."
    cd $BACKEND_PATH
    sudo -u www-data python3 -m venv venv
fi

# Install backend dependencies
print_status "Installing backend dependencies..."
cd $BACKEND_PATH
sudo -H -u www-data ./venv/bin/pip install -r requirements.txt
sudo -H -u www-data ./venv/bin/pip install gunicorn

# Copy service file from original directory
print_status "Copying service file..."
if [ -f "$ORIGINAL_DIR/backend/log-analyzer.service" ]; then
    sudo cp "$ORIGINAL_DIR/backend/log-analyzer.service" /etc/systemd/system/
    print_status "Service file copied successfully"
else
    print_error "Service file not found at $ORIGINAL_DIR/backend/log-analyzer.service"
    print_status "Available files in original directory:"
    ls -la "$ORIGINAL_DIR" || true
    exit 1
fi
sudo systemctl daemon-reload

print_status "Deploying Frontend..."

# Build frontend from original directory
print_status "Building Next.js application..."
cd "$ORIGINAL_DIR/frontend"
npm install
npm run build

# Copy built files to deployment directory
print_status "Copying built files..."
sudo cp -r out/* $FRONTEND_BUILD_PATH/

# Set proper permissions for frontend
sudo chown -R www-data:www-data $FRONTEND_BUILD_PATH

print_status "Configuring Nginx..."

# Create nginx configuration
sudo tee /etc/nginx/sites-available/log-analyzer > /dev/null <<EOF
server {
    listen 80;
    server_name sagestack.org www.sagestack.org;

    # Log Analyzer Frontend
    location /log-analyzer/ {
        alias $FRONTEND_BUILD_PATH/;
        index index.html;
        try_files \$uri \$uri/ /log-analyzer/index.html;
    }

    # Log Analyzer Backend API
    location /log-analyzer/api/ {
        proxy_pass http://127.0.0.1:5000/;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Your existing configurations...
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }

    location / {
        root /var/www/portfolio;
        index index.html;
        try_files \$uri \$uri/ /index.html;
    }

    location /support-chat/api/ {
        proxy_pass http://127.0.0.1:8000; 
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /support-chat/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /content-generator/ {
        proxy_pass http://127.0.0.1:3100;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /content-generator/api/ {
        proxy_pass http://127.0.0.1:8100;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /_next/static/development/_devMiddlewareManifest.json {
        access_log off;
        log_not_found off;
        expires -1;
        proxy_pass http://localhost:3000;
    }

    location /recipe-portal/api/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /recipe-portal/ {
      root /var/www/rec;
      index index.html;
      try_files \$uri \$uri/ /recipe-portal/index.html;
    }
}
EOF

# Enable the site
sudo ln -sf /etc/nginx/sites-available/log-analyzer /etc/nginx/sites-enabled/

# Test nginx configuration
sudo nginx -t

if [ $? -eq 0 ]; then
    print_status "Nginx configuration is valid"
else
    print_error "Nginx configuration is invalid"
    exit 1
fi

# Start/restart services
print_status "Starting services..."

# Start the backend service
sudo systemctl enable log-analyzer.service
sudo systemctl restart log-analyzer.service

# Reload nginx
sudo systemctl reload nginx

# Check service status
print_status "Checking service status..."
sudo systemctl status log-analyzer.service --no-pager

print_status "✅ Deployment completed successfully!"
print_status "🌐 Frontend: http://sagestack.org/log-analyzer/"
print_status "🔧 Backend API: http://sagestack.org/log-analyzer/api/"
print_status "📊 Service status: sudo systemctl status log-analyzer.service"
print_status "🔄 To update: Run this script again to pull latest changes" 