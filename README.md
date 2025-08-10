# Proxy Mock Server - Features Overview

A powerful Node.js HTTP proxy and mock server with advanced request/response management, filtering capabilities, and configurable response delays.

## 🚀 Core Features

### **HTTP Request Handling**
- **Mock Responses**: Return predefined JSON, text, HTML, or file-based responses
- **Proxy Requests**: Forward requests to external APIs with optional HTTP proxy support
- **Wildcard Routing**: Support for dynamic path matching (e.g., `/api/users/*`)
- **Multiple HTTP Methods**: GET, POST, PUT, DELETE, PATCH, and wildcard method matching

### **Advanced Filtering System**
- **Request Filters**: Route requests based on:
  - Query parameters
  - HTTP headers
  - URL patterns
  - Request body content (with nested field support)
- **Filter Operators**: equals, not_equals, contains, not_contains, regex, not_regex
- **Logic Operators**: AND/OR combinations for multiple filters

### **Response Management**
- **Multiple Response Types**: JSON, Text, HTML, File-based responses
- **Status Code Control**: Return any HTTP status code (100-599)
- **Custom Headers**: Set response headers per scenario
- **Response Delay**: ⏱️ **NEW** - Configurable response delays (0-300,000ms) to simulate:
  - Network latency
  - API throttling
  - Processing time
  - Slow backend services

### **Scenario Management**
- **Multi-scenario Endpoints**: Each endpoint can have multiple response scenarios
- **Conditional Responses**: Route to different scenarios based on request filters
- **Default Behaviors**: 
  - First scenario (default)
  - Round-robin rotation
  - Named scenario selection
- **Enable/Disable Endpoints**: Toggle endpoints on/off without deletion

### **File Organization**
- **Multi-file Support**: Organize scenarios across multiple JSON files
- **File Management**: Create, rename, delete scenario files via API
- **Source Tracking**: Each scenario tracks its source file for organization

### **Proxy Capabilities**
- **Direct Proxying**: Forward requests directly to target servers
- **HTTP Proxy Support**: Route through corporate/system HTTP proxies
- **HTTPS Support**: Handle HTTPS targets through HTTP proxies (CONNECT method)
- **Path Rewriting**: Automatic path rewriting for wildcard proxy routes
- **Proxy Authentication**: Support for proxy username/password authentication

### **Security & Configuration**
- **CORS Support**: Configurable Cross-Origin Resource Sharing
- **Secret Masking**: Automatic masking of sensitive data in logs
- **Directory Security**: Protection against path traversal attacks
- **Management API Control**: Enable/disable management interface

### **Logging & Monitoring**
- **Comprehensive Logging**: Request/response logging with configurable levels
- **File & Console Logging**: Dual output with color-coded console logs
- **Request Tracing**: Unique request IDs for tracking
- **Performance Metrics**: Response times and server statistics
- **Detailed Proxy Logging**: Track proxy requests and errors

### **Management Interface**
- **Web-based GUI**: Modern, responsive management interface at `/management`
- **Real-time Editing**: Create and modify scenarios through web UI
- **Visual Organization**: File-grouped scenario display
- **Import/Export**: JSON import/export functionality
- **Server Synchronization**: Sync local changes with running server

## 📁 Directory Structure

```
project/
├── server.js              # Main server file
├── management.html         # Web management interface
├── scenarios-db/          # Scenario JSON files
│   ├── default.json       # Default scenarios
│   ├── auth.json          # Authentication scenarios
│   └── payments.json      # Payment API scenarios
├── response-files/        # Static response files
│   ├── templates/         # HTML templates
│   ├── assets/           # CSS, JS, images
│   └── api-docs.html     # API documentation
└── logs/                 # Server logs
    └── proxy-YYYY-MM-DD.log
```

## ⚙️ Configuration Options

### Environment Variables
```bash
PORT=3001                           # Server port
LOG_LEVEL=info                      # debug, info, warn, error
ENABLE_MANAGEMENT_API=true          # Enable/disable management interface
RESPONSE_FILES_ROOT=./response-files # Response files directory
SCENARIOS_DB=./scenarios-db         # Scenarios directory
LOG_FOLDER=./logs                   # Log output directory

# CORS Configuration
CORS_ENABLED=true
CORS_ORIGIN=*
CORS_METHODS=GET,POST,PUT,DELETE,PATCH,OPTIONS
CORS_CREDENTIALS=true

# HTTP Proxy Configuration (for outbound requests)
HTTP_PROXY_ENABLED=false
HTTP_PROXY_HOST=proxy.company.com
HTTP_PROXY_PORT=8080
HTTP_PROXY_USERNAME=user
HTTP_PROXY_PASSWORD=pass
```

### Scenario File Example
```json
{
  "GET /api/users": {
    "enabled": true,
    "scenarios": [
      {
        "name": "Slow Response",
        "actionType": "mock",
        "filters": [
          {
            "type": "query",
            "field": "slow",
            "operator": "equals",
            "value": "true"
          }
        ],
        "response": {
          "statusCode": 200,
          "headers": {
            "Content-Type": "application/json"
          },
          "bodyType": "json",
          "body": {"users": []},
          "delay": 3000
        }
      },
      {
        "name": "Fast Response",
        "actionType": "mock",
        "filters": [],
        "response": {
          "statusCode": 200,
          "headers": {
            "Content-Type": "application/json"
          },
          "bodyType": "json",
          "body": {"users": [{"id": 1, "name": "John"}]},
          "delay": 0
        }
      }
    ],
    "defaultBehavior": "first",
    "logicOperator": "and"
  },
  "POST /api/proxy/*": {
    "enabled": true,
    "scenarios": [
      {
        "name": "Proxy to External API",
        "actionType": "proxy",
        "filters": [],
        "response": {
          "destinationUrl": "https://jsonplaceholder.typicode.com",
          "useSystemProxy": false,
          "delay": 1000
        }
      }
    ],
    "defaultBehavior": "first",
    "logicOperator": "and"
  }
}
```

## 🚀 Quick Start

1. **Install Dependencies**
   ```bash
   npm install express cors
   ```

2. **Start Server**
   ```bash
   node server.js [scenarios-directory]
   ```

3. **Access Management Interface**
   ```
   http://localhost:3001/management
   ```

4. **API Endpoints**
   - `GET /apixxx/scenarios` - List all scenarios
   - `POST /apixxx/scenarios` - Update scenarios
   - `POST /apixxx/toggle-endpoint` - Enable/disable endpoints
   - `GET /apixxx/status` - Server status and statistics

## 💡 Use Cases

- **API Development**: Mock external APIs during development
- **Testing**: Create test scenarios with various response conditions
- **Performance Testing**: Simulate slow APIs with response delays
- **Integration Testing**: Test error conditions and edge cases
- **Development Proxy**: Route requests to different environments
- **Load Testing**: Test application behavior under slow network conditions
- **Demonstration**: Show different API responses for demos

## 🔧 Advanced Features

### Response Delay Examples
```javascript
// Simulate slow network (2 seconds)
"delay": 2000

// Simulate API throttling (5 seconds)
"delay": 5000

// Simulate timeout scenario (30 seconds)
"delay": 30000

// No delay (immediate response)
"delay": 0
```

### Filter Examples
```javascript
// Query parameter filter
{
  "type": "query",
  "field": "version",
  "operator": "equals",
  "value": "v2"
}

// Header-based routing
{
  "type": "header",
  "field": "authorization",
  "operator": "contains",
  "value": "Bearer"
}

// Request body filtering
{
  "type": "body",
  "field": "user.role",
  "operator": "equals",
  "value": "admin"
}

// URL pattern matching
{
  "type": "url",
  "operator": "regex",
  "value": "/api/v[0-9]+/users"
}
```

This server provides a comprehensive solution for HTTP mocking and proxying with enterprise-grade features for development, testing, and integration scenarios.