# Log Analyzer Deployment Guide

This guide will help you deploy the Log Analyzer application on your server with proper nginx configuration.

## Prerequisites

- Ubuntu/Debian server
- Python 3.8+
- Node.js 18+
- Nginx
- sudo access

## Quick Deployment

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Initial deployment"
   git push origin main
   ```

2. **On your server, download and run the deployment script:**
   ```bash
   # Download the deployment script
   wget https://raw.githubusercontent.com/YOUR_USERNAME/log-analyzer/main/deploy.sh
   chmod +x deploy.sh
   
   # Edit the script to update your repository URL
   nano deploy.sh
   # Update REPO_URL="https://github.com/YOUR_USERNAME/log-analyzer.git"
   
   # Run the deployment
   ./deploy.sh
   ```

## Manual Deployment Steps

### 1. Backend Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/YOUR_USERNAME/log-analyzer.git /tmp/log-analyzer-deploy
   ```

2. **Create deployment directory:**
   ```bash
   sudo mkdir -p /var/www/log-analyzer/backend
   sudo chown -R www-data:www-data /var/www/log-analyzer/backend
   ```

3. **Copy backend files:**
   ```bash
   sudo cp -r /tmp/log-analyzer-deploy/backend/* /var/www/log-analyzer/backend/
   ```

3. **Set up Python virtual environment:**
   ```bash
   cd /var/www/log-analyzer/backend
   sudo -u www-data python3 -m venv venv
   sudo -u www-data ./venv/bin/pip install -r requirements.txt
   sudo -u www-data ./venv/bin/pip install gunicorn
   ```

4. **Install systemd service:**
   ```bash
   sudo cp backend/log-analyzer.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable log-analyzer.service
   sudo systemctl start log-analyzer.service
   ```

### 2. Frontend Deployment

1. **Build the Next.js application:**
   ```bash
   cd /tmp/log-analyzer-deploy/frontend
   npm install
   npm run build
   ```

2. **Deploy static files:**
   ```bash
   sudo mkdir -p /var/www/log-analyzer-frontend
   sudo cp -r out/* /var/www/log-analyzer-frontend/
   sudo chown -R www-data:www-data /var/www/log-analyzer-frontend
   ```

3. **Clean up:**
   ```bash
   rm -rf /tmp/log-analyzer-deploy
   ```

### 3. Nginx Configuration

The deployment script will automatically update your nginx configuration. The new configuration adds:

- **Frontend**: `http://sagestack.org/log-analyzer/`
- **Backend API**: `http://sagestack.org/log-analyzer/api/`

### 4. Update Frontend API Base URL

You need to update the frontend to use the correct API base URL. In your frontend code, update axios calls to use:

```javascript
// Instead of localhost:5000, use:
const API_BASE_URL = '/log-analyzer/api';
```

## Service Management

### Check service status:
```bash
sudo systemctl status log-analyzer.service
```

### Restart backend:
```bash
sudo systemctl restart log-analyzer.service
```

### View logs:
```bash
sudo journalctl -u log-analyzer.service -f
```

### Reload nginx:
```bash
sudo systemctl reload nginx
```

## Troubleshooting

### Backend Issues:
1. Check if the service is running: `sudo systemctl status log-analyzer.service`
2. Check logs: `sudo journalctl -u log-analyzer.service -f`
3. Verify port 5000 is not in use: `sudo netstat -tlnp | grep :5000`

### Frontend Issues:
1. Check if files are copied: `ls -la /var/www/log-analyzer-frontend/`
2. Check nginx configuration: `sudo nginx -t`
3. Check nginx logs: `sudo tail -f /var/log/nginx/error.log`

### Nginx Issues:
1. Test configuration: `sudo nginx -t`
2. Check syntax: `sudo nginx -T`
3. Reload nginx: `sudo systemctl reload nginx`

## File Structure After Deployment

```
/var/www/
├── log-analyzer/
│   └── backend/
│       ├── venv/
│       ├── app.py
│       ├── requirements.txt
│       └── gunicorn_config.py
└── log-analyzer-frontend/
    ├── index.html
    ├── _next/
    └── static/
```

## URLs

- **Frontend**: `http://sagestack.org/log-analyzer/`
- **Backend API**: `http://sagestack.org/log-analyzer/api/`
- **Health Check**: `http://sagestack.org/log-analyzer/api/health`

## Security Notes

1. The backend runs on `127.0.0.1:5000` (localhost only)
2. All external access goes through nginx proxy
3. Static files are served directly by nginx
4. CORS is handled by the nginx proxy configuration

## Updates

To update the application:

1. **Backend**: Copy new files and restart service
   ```bash
   sudo cp -r backend/* /var/www/log-analyzer/backend/
   sudo systemctl restart log-analyzer.service
   ```

2. **Frontend**: Rebuild and copy new files
   ```bash
   cd frontend
   npm run build
   sudo cp -r out/* /var/www/log-analyzer-frontend/
   ``` 