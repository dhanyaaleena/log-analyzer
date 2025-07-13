# Log Analyzer - Security Analytics Platform

A simple tool that analyzes web server logs to detect security threats and suspicious activities using machine learning and AI.

**Options:**
- **Live Demo**: Visit the deployed application
- **Local Setup**: Run with Docker

## Quick Start

### Option 1: Live Demo
Visit [https://www.sagestack.org/log-analyzer/](https://www.sagestack.org/log-analyzer/) to test the application.

**Default Login Credentials**
   - **Username**: `admin`
   - **Password**: `admin123`
   Alternatively Register new account.

Sample logs files to test:
https://github.com/dhanyaaleena/log-analyzer/blob/master/synthetic_web_logs_50.log
https://github.com/dhanyaaleena/log-analyzer/blob/master/synthetic_web_logs_100.log
https://github.com/dhanyaaleena/log-analyzer/blob/master/synthetic_web_logs_500.log

Lime Demo is AI Enabled.

### Option 2: Run Locally with Docker

#### Prerequisites
- Docker and Docker Compose installed
- Google Gemini API key (optional, for AI-powered threat analysis and explanations)


### Docker Deployment

1. **Clone the repository**
   ```bash
   git clone https://github.com/dhanyaaleena/log-analyzer.git
   cd log-analyzer
   ```

2. **Make the Docker script executable**
   ```bash
   chmod +x docker-run.sh
   ```

3. **Set up Google API Key for AI Analysis (Optional)**
   ```bash
   # Copy the example environment file (in project root, outside Docker)
   cp env.example .env
   
   # Edit .env and add your Google API key
   # Get your API key from: https://makersuite.google.com/app/apikey
   # GOOGLE_API_KEY=your_actual_api_key_here
   ```
   
   **File Structure:**
   ```
   log-analyzer/
   ├── .env                    ← Create this file here (project root)
   ├── docker-compose.yml
   ├── env.example
   ├── backend/
   ├── frontend/
   └── ...
   ```

4. **Run the Docker setup script**
   ```bash
   ./docker-run.sh
   ```

   This script will:
   - Build all Docker images with no cache
   - Start PostgreSQL database
   - Initialize database tables automatically
   - Create default user (admin/admin123)
   - Start Flask backend API
   - Start Next.js frontend
   - Show analytics of the logs in the dashboard

5. **Access the Application**
   - **Frontend**: http://localhost:3000/log-analyzer/
   - **Backend API**: http://localhost:5000/log-analyzer/api/
   - **Database**: PostgreSQL on localhost:5433

6. **Default Login Credentials**
   - **Username**: `admin`
   - **Password**: `admin123`
   Alternatively Register new account(no validation is required).

**Note**: The Google API key is optional. Without it, the system will still detect threats using machine learning, but won't provide AI-powered explanations and recommendations.

### Test Log Files

The repository includes sample log files for testing:
- **`synthetic_web_logs_100.log`** 
- **`synthetic_web_logs_50.log`** 
- **`synthetic_web_logs_500.log`** 

These files contain realistic web server logs with embedded security threats including:
- Brute force attacks (multiple 403 errors)
- Automated tools (curl, wget, python scripts)
- Suspicious domains (typosquatting, malicious TLDs)
- Data exfiltration (unusual data transfers)
- Rare domain access patterns


## How It Works

The platform implements a three-tier architecture consisting of:

1. **Frontend Layer**: Next.js-based web interface providing analytics dashboard
2. **Backend Layer**: Flask API with integrated machine learning pipeline
3. **Data Layer**: PostgreSQL database with log files and analysis results

### Architecture Diagram
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend API   │    │   Database      │
│   (Next.js)     │◄──►│   (Flask)       │◄──►│   (PostgreSQL)  │
│                 │    │ • Log Parsing   │    │                 │
│ • Dashboard     │    │ • ML Models     │    │ • Log Files     │
│ • User Auth     │    │ • LLM Service   │    │ • Anomalies     │
│ • Upload        │    │ • Rule Engine   │    │ • Users         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   ML Pipeline   │
                       │                 │
                       │ • Isolation     │
                       │   Forest        │
                       │ • LOF           │
                       └─────────────────┘
```



### Data Flow Architecture

The system processes log entries through a multi-stage pipeline:
- Log parsing and feature extraction
- Rule-based security analysis
- Machine learning anomaly detection
- Confidence scoring and threat classification
- AI-powered explanation generation

## Log File Processing

The system processes web server logs in the following standardized format:

**Log Entry Structure**
```
Timestamp Source_IP Destination_IP Domain Action Method Status_Code User_Agent Bytes_Sent Bytes_Received
```

**Field Definitions**
- **Timestamp**: ISO 8601 format (YYYY-MM-DD HH:MM:SS)
- **Source IP**: Internal network IP address (192.168.x.x)
- **Destination IP**: External server IP address
- **Domain**: Requested domain name
- **Action**: Security action taken (Allowed/Blocked)
- **Method**: HTTP request method (GET/POST/PUT/DELETE)
- **Status Code**: HTTP response status code
- **User Agent**: Client browser/application identifier
- **Bytes Sent**: Data transmitted from client
- **Bytes Received**: Data received by client

### Log Parsing Implementation

**Parser Architecture**
The system implements a space-delimited parsing algorithm that processes log entries line by line:

**Parsing Algorithm**
- Line-by-line file processing with streaming approach
- Space-separated field extraction using split operation
- Fixed-field parsing with 10 expected components
- Error handling for malformed or incomplete entries

**Data Validation**
- IP address format verification
- Timestamp parsing and validation using datetime.strptime
- HTTP status code range checking
- User agent string normalization


## Machine Learning Implementation

The system implements a dual-algorithm approach for anomaly detection:

**Isolation Forest Algorithm**
- Uses random partitioning to find unusual data points
- Expects 10% of data to be anomalies
- Uses 100 decision trees for reliable detection
- Works by isolating data points that are different from the majority

**Local Outlier Factor (LOF)**
- Compares each data point to its 20 nearest neighbors
- Identifies points that are far from their neighbors
- Also expects 10% of data to be anomalies
- Measures how isolated each point is from its local group

### Feature Engineering Pipeline

The system extracts seven numerical features from each log entry:
- HTTP status code (normalized)
- Bytes transmitted (sent/received)
- Domain name length
- User agent string length
- Request blocking status (binary)
- HTTP method type (encoded)
- Request timestamp patterns

## Security Detection Engine

### Rule-Based Detection Framework

The system implements four primary security detection categories:

**Brute Force Attack Detection**
- Monitors multiple 403 errors from identical source IPs
- Implements minimum threshold of 2 attempts for pattern recognition
- Calculates confidence based on attempt frequency and distribution

**Information Gathering Detection**n
- Idetifies scanning patterns through request frequency analysis
- Detects access attempts to administrative endpoints

**Data Exfiltration Detection**
- Analyzes data transfer patterns using statistical thresholds
- Monitors unusual data volume transfers relative to baseline

**Malware and Phishing Detection**
- Implements domain reputation analysis
- Detects typosquatting patterns through string similarity algorithms
- Identifies suspicious top-level domains through blacklist comparison

## Configuration

### ML Model Parameters
```python
# Isolation Forest
contamination = 0.1  # Expected anomaly ratio
n_estimators = 100   # Number of trees
random_state = 42    # Reproducibility

# Local Outlier Factor
n_neighbors = 20     # Neighbor count
contamination = 0.1  # Expected anomaly ratio
```

### Confidence Thresholds
```python
# Minimum confidence for alerting
HIGH_CONFIDENCE = 0.8
MEDIUM_CONFIDENCE = 0.6
LOW_CONFIDENCE = 0.4
```

### Rule Engine Settings
```python
# Brute Force Detection
MIN_403_COUNT = 2
MIN_ATTEMPTS = 3

# Suspicious Domain Detection
SUSPICIOUS_TLDS = ['.xyz', '.top', '.cc', '.tk']
MAX_SUBDOMAINS = 2
```

## API Endpoints

### Analysis Endpoints
- `POST /analysis/run` - Run log analysis
- `GET /analysis/result/<file_id>` - Get analysis results
- `GET /analysis/dashboard/<file_id>` - Get dashboard metrics

### Upload Endpoints
- `POST /upload/file` - Upload log file
- `GET /upload/files` - List uploaded files

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/register` - User registration

## Tech Stack

- **Scikit-learn**: ML algorithms and preprocessing
- **Google Gemini**: LLM integration and analysis
- **Flask**: Backend framework
- **Next.js**: Frontend framework
- **PostgreSQL**: Database system 