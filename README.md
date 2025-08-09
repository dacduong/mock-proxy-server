# 🚀 Proxy/Mock Server v1.0

A powerful Node.js HTTP proxy and mock server with **native proxy implementation**, advanced request filtering, response mocking, and multi-file scenario management capabilities. Perfect for API development, testing, and integration workflows.

## ✨ Features

### Core Capabilities
- **🔄 Native HTTP Proxy & Mock Server**: Route requests to external APIs or return custom mock responses using built-in Node.js modules
- **📁 Multi-File Scenario Management**: Organize scenarios across multiple JSON files with full CRUD operations
- **🎯 Advanced Request Filtering**: Filter by headers, query parameters, URL patterns, and request body content
- **📂 Configurable File Responses**: Secure static file serving with configurable root directory and MIME type detection
- **🔀 Multiple Response Strategies**: First match, round-robin, or named scenario selection
- **🌐 CORS Support**: Configurable cross-origin resource sharing
- **📝 Enhanced Logging System**: Structured logging with colors, levels, request tracing, and sensitive data masking
- **🎨 Enhanced Web Management UI**: Modern browser-based interface with file grouping and collapsible sections
- **🔍 Wildcard URL Matching**: Support for dynamic URL patterns with `*` wildcards
- **🔐 Native HTTP Proxy Support**: Route outbound requests through corporate proxies without external dependencies

### 🆕 Native Proxy Implementation (v1.0)
- **⚡ Zero External Dependencies**: Uses only Node.js built-in `http`, `https`, and `url` modules
- **🔧 Direct Proxy Control**: Full control over proxy behavior and error handling
- **🚀 Better Performance**: Native implementation without middleware overhead
- **🛡️ Enhanced Security**: No external proxy agent vulnerabilities
- **📊 Detailed Proxy Logging**: Comprehensive logging of proxy operations and tunneling
- **🔒 HTTPS Tunneling**: Proper CONNECT method handling for HTTPS through HTTP proxy
- **⚠️ Corporate Proxy Support**: Username/password authentication for corporate proxies

### 🆕 Advanced Logging Features (v1.0)
- **🎨 Colored Console Output**: Color-coded log levels (debug, info, warn, error)
- **🔍 Request Tracing**: Unique request IDs for complete request lifecycle tracking
- **⏱️ Performance Metrics**: Request duration tracking and server statistics
- **📱 Log Levels**: Configurable logging verbosity (debug, info, warn, error)
- **🎭 Sensitive Data Masking**: Enhanced masking of authorization headers, cookies, and tokens
- **📁 Daily Log Rotation**: Automatic daily log file creation and management
- **💾 Structured File Logging**: JSON-formatted logs with detailed request/response data

### 🆕 Advanced UI Features (v1.0)
- **📂 File-Based Organization**: Group endpoints by scenario files with visual hierarchy
- **🔽 Collapsible File Sections**: Expand/collapse file groups with state persistence
- **➕ Dynamic File Management**: Create, rename, delete scenario files through the UI
- **📤 Individual File Export**: Export specific scenario files separately
- **🎯 Quick Actions**: Add endpoints directly to specific files
- **📊 Real-Time Statistics**: Show endpoint counts per file
- **🗂️ Server-Side File Operations**: Actual file rename/delete operations on the server

### Security Features
- **🛡️ Directory Traversal Protection**: Prevents unauthorized file system access
- **🔒 Response Files Root**: All file responses served from configured secure directory
- **🎭 Sensitive Data Masking**: Automatic masking of tokens, passwords, and JWT in logs
- **✅ File Path Validation**: Secure file path resolution with root directory enforcement

## 📦 Installation

### Prerequisites
- Node.js 18+ 
- npm or yarn

### 🆕 Minimal Dependencies (v1.0)
```bash
# Only essential dependencies - no proxy agents needed!
npm install express cors
```

### Development Dependencies
```bash
npm install --save-dev axios
```

## 🚀 Quick Start

### 1. Basic Setup
```bash
# Start the server
node server.js

# Start with custom scenarios directory
node server.js ./my-scenarios

# Start with custom response files location
RESPONSE_FILES_ROOT=./my-responses node server.js
```

### 2. Environment Configuration
```bash
# Set custom directories
RESPONSE_FILES_ROOT=./static-files node server.js

# Configure logging levels
LOG_LEVEL=debug LOG_DETAILS=true LOG_PROXY_DETAILS=true node server.js

# Configure HTTP proxy for outbound requests
HTTP_PROXY_ENABLED=true HTTP_PROXY_HOST=proxy.company.com HTTP_PROXY_PORT=8080 \
HTTP_PROXY_USERNAME=user HTTP_PROXY_PASSWORD=pass node server.js
```

### 3. Access Enhanced Management Interface
```
http://localhost:3001/management
```

## 📁 Enhanced Directory Structure

```
project-root/
├── server.js                 # 🆕 Native proxy implementation (no external proxy deps)
├── management.html           # Enhanced web management interface
├── test-standalone.js        # Comprehensive test suite
├── scenarios-db/            # Multi-file scenario configurations
│   ├── default.json         # Default scenarios (cannot be deleted)
│   ├── auth.json           # Authentication scenarios
│   ├── users.json          # User management scenarios
│   ├── payments.json       # Payment processing scenarios
│   └── external-apis.json  # External API proxying scenarios
├── response-files/         # Static files for file-based responses
│   ├── api-docs.html       # API documentation
│   ├── templates/          # Response templates
│   │   ├── email.html      # Email templates
│   │   └── reports/        # Report templates
│   ├── assets/             # Static assets
│   │   ├── styles.css      # CSS stylesheets
│   │   ├── scripts.js      # JavaScript files
│   │   └── images/         # Image assets
│   └── data/               # JSON data files
│       ├── products.json   # Product catalog
│       └── users.json      # User data
├── scenarios-db-sample/    # Sample scenarios for testing (optional)
├── response-files-sample/  # Sample response files for testing (optional)
└── logs/                   # 🆕 Enhanced request/response logs (auto-created)
    ├── proxy-2024-01-15.log  # Daily log rotation
    └── proxy-2024-01-16.log  # JSON-formatted structured logs
```

## ⚙️ Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | Server port |
| `LOG_FOLDER` | `./logs` | Directory for log files |
| `RESPONSE_FILES_ROOT` | `./response-files` | Root directory for file-based responses |
| `ENABLE_CONSOLE_LOG` | `true` | Enable console logging |
| `ENABLE_FILE_LOG` | `true` | Enable file logging |
| `LOG_DETAILS` | `true` | Log request/response details |
| `LOG_PROXY_DETAILS` | `true` | Log proxy operation details |
| `LOG_LEVEL` | `info` | 🆕 Logging level: debug, info, warn, error |
| `CORS_ENABLED` | `true` | Enable CORS support |
| `CORS_ORIGIN` | `*` | Allowed CORS origins |
| `CORS_METHODS` | `GET,POST,PUT,DELETE,PATCH,OPTIONS` | Allowed HTTP methods |
| `CORS_ALLOWED_HEADERS` | `Content-Type,Authorization,X-Requested-With` | Allowed headers |
| `CORS_CREDENTIALS` | `true` | Allow credentials in CORS requests |
| `HTTP_PROXY_ENABLED` | `false` | 🆕 Enable outbound HTTP proxy (native implementation) |
| `HTTP_PROXY_HOST` | - | Proxy server hostname |
| `HTTP_PROXY_PORT` | - | Proxy server port |
| `HTTP_PROXY_USERNAME` | - | 🆕 Proxy username for authentication |
| `HTTP_PROXY_PASSWORD` | - | 🆕 Proxy password for authentication |
| `HTTP_PROXY_PROTOCOL` | `http` | Proxy protocol: http or https |

## 🎨 Enhanced Management Interface

### File-Based Organization
The management interface organizes endpoints by scenario files with:

```
📄 auth.json                           [5 endpoints] ▼
├─ ➕ Add Endpoint  📤 Export  ✏️ Rename  🗑️ Delete
├─ POST /api/login                      [Edit] [Delete]
├─ POST /api/logout                     [Edit] [Delete]
├─ GET /api/profile                     [Edit] [Delete]
└─ PUT /api/password                    [Edit] [Delete]

📄 users.json                          [3 endpoints] ▲ (collapsed)

📄 payments.json                       [7 endpoints] ▼
├─ ➕ Add Endpoint  📤 Export  ✏️ Rename  🗑️ Delete
├─ POST /api/payments                   [Edit] [Delete]
├─ GET /api/payments/history           [Edit] [Delete]
└─ PUT /api/payments/refund            [Edit] [Delete]
```

### File Management Operations

#### Creating New Scenario Files
1. Click **"📁 Add Scenario File"**
2. Enter filename (e.g., "payments", "analytics")
3. Optional description for documentation
4. File automatically appears in the interface
5. Auto-opens "Add Endpoint" modal for new file

#### File Operations
- **➕ Add Endpoint**: Creates endpoints directly in specific files
- **📤 Export File**: Downloads individual file as JSON
- **✏️ Rename File**: Changes filename with server-side validation
- **🗑️ Delete File**: Removes file and all endpoints (with confirmation)

#### UI Features
- **🔄 State Persistence**: Remembers which file sections are collapsed
- **⚡ Real-Time Updates**: Changes immediately reflected in the interface
- **📱 Responsive Design**: Works on mobile and desktop devices
- **📊 Statistics**: Shows endpoint count per file
- **🎨 Modern Styling**: Gradient headers, smooth animations, hover effects

## 🎯 Usage Examples

### File Response (Default Type)
```json
{
  "name": "API Documentation",
  "actionType": "mock",
  "response": {
    "statusCode": 200,
    "bodyType": "file",
    "filePath": "api-docs.html"
  }
}
```

### Mock JSON Response
```json
{
  "name": "Success Response",
  "actionType": "mock",
  "response": {
    "statusCode": 200,
    "headers": { "Content-Type": "application/json" },
    "bodyType": "json",
    "body": { "status": "success" }
  }
}
```

### 🆕 Native Proxy Request with System Proxy
```json
{
  "name": "External API Proxy - Native Implementation",
  "actionType": "proxy", 
  "response": {
    "destinationUrl": "https://api.external.com",
    "useSystemProxy": true
  }
}
```

### Advanced Filtering with Regex
```json
{
  "filters": [
    {
      "type": "header",
      "field": "Authorization", 
      "operator": "contains",
      "value": "Bearer"
    },
    {
      "type": "query",
      "field": "email",
      "operator": "regex", 
      "value": "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$"
    }
  ]
}
```

### File Path Examples
```json
{
  "response": {
    "bodyType": "file",
    "filePath": "templates/welcome.html"     // ✅ Relative to response-files root
  }
}

// File resolution:
// "api-docs.html" → ./response-files/api-docs.html
// "templates/email.html" → ./response-files/templates/email.html
// "assets/styles.css" → ./response-files/assets/styles.css
```

## 🔧 API Reference

### Enhanced Management Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/apixxx/scenarios` | GET | Retrieve all scenarios with file information |
| `/apixxx/scenarios` | POST | Update all scenarios |
| `/apixxx/files` | GET | List available scenario files |
| `/apixxx/rename-file` | POST | Rename a scenario file on the server |
| `/apixxx/delete-file/:fileName` | DELETE | Delete a scenario file from the server |
| `/management` | GET | Access enhanced web management interface |

### File Management API

#### Rename File
```bash
POST /apixxx/rename-file
Content-Type: application/json

{
  "oldFileName": "auth",
  "newFileName": "authentication"
}

Response:
{
  "success": true,
  "message": "File renamed from auth.json to authentication.json",
  "oldFileName": "auth",
  "newFileName": "authentication"
}
```

#### Delete File
```bash
DELETE /apixxx/delete-file/payments

Response:
{
  "success": true,
  "message": "File payments.json deleted successfully",
  "fileName": "payments",
  "removedEndpoints": 7
}
```

## 🧪 Enhanced Testing

### Running the Test Suite
```bash
# Create sample directories (required for full testing)
mkdir scenarios-db-sample response-files-sample

# Add sample scenario files
cp scenarios-sample.json scenarios-db-sample/default.json

# Add sample response files (see response-files-sample structure)
# Create HTML, JSON, CSS files in response-files-sample/

# Run comprehensive tests
node test-standalone.js
```

### 🆕 Test Features
- ✅ **Native proxy implementation** validation
- ✅ **Multi-file scenario loading** validation
- ✅ **File response system** testing with MIME type detection
- ✅ **Security features** validation (directory traversal protection)
- ✅ **Duplicate endpoint detection** across files
- ✅ **Source file tracking** verification
- ✅ **Server-side file operations** testing
- ✅ **Enhanced logging system** validation
- ✅ **HTTP proxy authentication** testing
- ✅ **HTTPS tunneling** validation

### Manual Testing Examples
```bash
# Test file response (default type)
curl http://localhost:3001/api/docs

# Test native proxy with debugging
LOG_LEVEL=debug node server.js &
curl http://localhost:3001/api/external-endpoint

# Test with custom response files root
RESPONSE_FILES_ROOT=./my-files node server.js
curl http://localhost:3001/api/templates/email

# Test file management API
curl -X POST http://localhost:3001/apixxx/rename-file \
  -H "Content-Type: application/json" \
  -d '{"oldFileName": "test", "newFileName": "testing"}'

# Test file deletion
curl -X DELETE http://localhost:3001/apixxx/delete-file/old-scenarios

# Test proxy with authentication
HTTP_PROXY_ENABLED=true HTTP_PROXY_HOST=proxy.company.com \
HTTP_PROXY_PORT=8080 HTTP_PROXY_USERNAME=user HTTP_PROXY_PASSWORD=pass \
node server.js
```

## 🚀 Production Deployment

### 🆕 Minimal Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only essential dependencies (no proxy agents!)
RUN npm ci --only=production

COPY . .

# Create required directories
RUN mkdir -p scenarios-db response-files logs

# Expose port
EXPOSE 3001

# Start with production logging
ENV LOG_LEVEL=warn
ENV LOG_DETAILS=false
ENV LOG_PROXY_DETAILS=false

CMD ["node", "server.js"]
```

### Multi-File Organization Best Practices
```bash
# Organize by feature/team
scenarios-db/
├── default.json      # Core system endpoints (protected)
├── auth.json        # Authentication team scenarios
├── payments.json    # Payments team scenarios  
├── users.json       # User management team scenarios
├── analytics.json   # Analytics team scenarios
└── external.json    # External API integrations

# Organize response files by type and purpose
response-files/
├── templates/       # HTML email and report templates
│   ├── emails/
│   └── reports/
├── data/           # JSON data files and catalogs
│   ├── products.json
│   └── users.json
├── assets/         # Static assets (CSS, JS, images)
│   ├── css/
│   ├── js/
│   └── images/
└── docs/           # API documentation files
    ├── api-v1.html
    └── api-v2.html
```

## 🔒 Enhanced Security

### Native Proxy Security
- **🛡️ No External Dependencies**: Eliminates security vulnerabilities from proxy agent libraries
- **🔒 Direct Control**: Full control over proxy request handling and security
- **🎭 Enhanced Authentication**: Secure handling of proxy credentials
- **📝 Detailed Audit Logs**: Complete request tracing for security monitoring

### File Response Security
- **🛡️ Path Validation**: All file paths resolved relative to `RESPONSE_FILES_ROOT`
- **🚫 Directory Traversal**: Attempts to access `../` paths are blocked
- **🔒 Root Enforcement**: Files must exist within configured root directory
- **🎯 MIME Type Detection**: Automatic Content-Type headers (.html, .json, .css, .js, .xml, .txt)
- **⚠️ Security Violations**: Returns 403 for path traversal attempts

### Data Protection
- **🎭 Enhanced Masking**: Sensitive data (JWT, passwords, tokens, cookies) masked in logs
- **📝 Source Tracking**: All log entries include source file information
- **🌐 CORS Control**: Configurable cross-origin restrictions
- **🔍 Request Tracing**: Unique request IDs for security audit trails

## 🆘 Troubleshooting

### 🆕 Native Proxy Troubleshooting

**Proxy requests fail with connection errors**:
- Enable debug logging: `LOG_LEVEL=debug node server.js`
- Check proxy configuration: host, port, username, password
- Verify corporate proxy allows CONNECT method for HTTPS requests
- Check firewall rules for outbound connections

**HTTPS proxy tunneling fails**:
- Corporate proxies may block CONNECT method
- Try HTTP-only targets first to verify basic proxy functionality
- Check proxy logs for authentication failures
- Verify proxy credentials and encoding

**Performance issues with native proxy**:
- Native implementation should be faster than middleware
- Enable `LOG_PROXY_DETAILS=true` to identify bottlenecks
- Check network latency to target servers
- Monitor memory usage during high-load scenarios

### Enhanced Troubleshooting

**Management UI file operations fail**:
- Verify server has write permissions to `scenarios-db/` directory
- Check server logs for detailed error messages
- Ensure filename follows validation rules (letters, numbers, hyphens, underscores only)
- Cannot rename or delete the `default.json` file

**File responses return 404**:
- Verify files exist in the configured `RESPONSE_FILES_ROOT` directory
- Check file path syntax in scenario configuration (use relative paths only)
- Ensure file paths don't contain directory traversal (`../`)
- Example: Use `templates/email.html` not `./templates/email.html`

**Server fails to start with duplicate endpoint error**:
- Check all JSON files in `scenarios-db/` for duplicate `{method} {path}` combinations
- Each endpoint can only exist in one file
- Server will log which files contain the duplicate

**Tests fail with "Sample scenarios not available"**:
- Create `scenarios-db-sample/` directory with JSON scenario files
- Optional: Create `response-files-sample/` directory for file response tests
- Copy `scenarios-sample.json` to `scenarios-db-sample/default.json`

### Debug Commands
```bash
# Enable verbose logging with request tracing
LOG_LEVEL=debug LOG_DETAILS=true LOG_PROXY_DETAILS=true node server.js

# Check response files directory
ls -la ./response-files/

# Test file response endpoint with headers
curl -v http://localhost:3001/api/docs

# Monitor real-time logs with request IDs
tail -f ./logs/proxy-$(date +%Y-%m-%d).log | grep "REQUEST.*\["

# Test proxy connectivity
curl -v -x http://proxy.company.com:8080 http://httpbin.org/ip

# Test native proxy with authentication
HTTP_PROXY_ENABLED=true HTTP_PROXY_HOST=proxy.company.com \
HTTP_PROXY_USERNAME=user HTTP_PROXY_PASSWORD=pass \
LOG_LEVEL=debug node server.js
```
---

Made with ❤️ for developers who need powerful API mocking and proxying capabilities with **native performance** and professional file organization and management.