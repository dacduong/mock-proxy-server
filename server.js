const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const http = require('http');
const https = require('https');
const url = require('url');
const util = require('util');

class ProxyMockServer {
  constructor(configPath = './scenarios-db', options = {}) {
    this.app = express();
    this.configPath = configPath;
    this.scenarios = {};
    this.scenarioFiles = {}; // Track which file each scenario belongs to
    this.config = {
      port: options.port || 3001,
      logFolder: options.logFolder || './logs',
      responseFilesRoot: options.responseFilesRoot || './response-files',
      maskSecrets: options.maskSecrets || [
        { pattern: /authorization["\s]*[:=]["\s]*([^"',}]+)/gi, replacement: 'authorization": "[MASKED]' },
        { pattern: /password["\s]*[:=]["\s]*([^"'\s,}]+)/gi, replacement: 'password": "[MASKED]' },
        { pattern: /token["\s]*[:=]["\s]*([^"'\s,}]+)/gi, replacement: 'token": "[MASKED]' }
      ],
      enableConsoleLog: options.enableConsoleLog !== false,
      enableFileLog: options.enableFileLog !== false,
      logDetails: options.logDetails !== false,
      logProxyDetails: options.logProxyDetails !== false,
      logLevel: options.logLevel || 'info', // 'debug', 'info', 'warn', 'error'
      // CORS configuration
      cors: {
        enabled: options.cors?.enabled !== false,
        origin: options.cors?.origin || '*',
        methods: options.cors?.methods || ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allowedHeaders: options.cors?.allowedHeaders || ['Content-Type', 'Authorization', 'X-Requested-With'],
        credentials: options.cors?.credentials !== false
      },
      // HTTP Proxy configuration for outbound requests
      httpProxy: {
        enabled: options.httpProxy?.enabled || false,
        host: options.httpProxy?.host,
        port: options.httpProxy?.port,
        username: options.httpProxy?.username,
        password: options.httpProxy?.password,
        protocol: options.httpProxy?.protocol || 'http'
      }
    };
    
    // Disable TLS certificate validation for development
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    
    this.initializeLogging();
    this.setupMiddleware();
    this.loadScenarios();
  }

  // Initialize logging system similar to simple-server
  initializeLogging() {
    this.logLevels = { debug: 0, info: 1, warn: 2, error: 3 };
    this.currentLogLevel = this.logLevels[this.config.logLevel] || 1;
  }

  // Enhanced logging function similar to simple-server
  log(level, message, data = null) {
    const levelNum = this.logLevels[level];
    
    if (levelNum < this.currentLogLevel) return;
    
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    
    // Console output with colors
    const colors = {
      debug: '\x1b[36m',   // Cyan
      info: '\x1b[32m',    // Green
      warn: '\x1b[33m',    // Yellow
      error: '\x1b[31m'    // Red
    };
    const reset = '\x1b[0m';
    
    if (this.config.enableConsoleLog) {
      console.log(`${colors[level] || ''}${logMessage}${reset}`);
      
      if (data) {
        console.log(`${colors[level] || ''}${util.inspect(data, { colors: true, depth: 3 })}${reset}`);
      }
    }
    
    // Write to log file
    if (this.config.enableFileLog) {
      this.writeToLogFile(logMessage, data);
    }
  }

  async writeToLogFile(logMessage, data) {
    try {
      await this.ensureLogFolder();
      const logFile = path.join(this.config.logFolder, `proxy-${new Date().toISOString().split('T')[0]}.log`);
      const logEntry = data ? `${logMessage}\n${JSON.stringify(data, null, 2)}\n\n` : `${logMessage}\n`;
      
      await fs.appendFile(logFile, logEntry);
    } catch (error) {
      console.error('Error writing to log file:', error);
    }
  }

  // Sanitize headers for logging (hide sensitive data)
  sanitizeHeaders(headers) {
    const sanitized = { ...headers };
    if (sanitized.authorization) sanitized.authorization = '[MASKED]';
    if (sanitized['proxy-authorization']) sanitized['proxy-authorization'] = '[MASKED]';
    if (sanitized.cookie) sanitized.cookie = '[MASKED]';
    return sanitized;
  }

  // Log request details similar to simple-server
  logRequestStart(req, routeType = 'mock') {
    const requestId = Math.random().toString(36).substr(2, 9);
    req.requestId = requestId;
    req.startTime = Date.now();
    
    const requestInfo = {
      requestId,
      method: req.method,
      url: req.originalUrl,
      headers: this.sanitizeHeaders(req.headers),
      routeType,
      timestamp: new Date().toISOString(),
      clientIP: req.connection.remoteAddress || req.socket.remoteAddress || 
                (req.connection.socket ? req.connection.socket.remoteAddress : null),
      userAgent: req.headers['user-agent'] || 'Unknown'
    };
    
    this.log('info', `=== REQUEST START [${requestId}] ===`);
    this.log('info', `${req.method} ${req.originalUrl}`);
    this.log('debug', requestInfo);
    
    return requestInfo;
  }

  // Log response details
  logRequestEnd(req, res, scenario, responseData, additionalInfo = {}) {
    const duration = Date.now() - (req.startTime || Date.now());
    const requestId = req.requestId || 'unknown';
    
    const responseInfo = {
      requestId,
      statusCode: res.statusCode,
      statusText: this.getStatusText(res.statusCode),
      headers: this.sanitizeHeaders(res.getHeaders()),
      scenario: scenario?.name || 'no-match',
      sourceFile: scenario?.sourceFile || 'unknown',
      duration: `${duration}ms`,
      timestamp: new Date().toISOString(),
      ...additionalInfo
    };
    
    const level = res.statusCode >= 400 ? 'error' : res.statusCode >= 300 ? 'warn' : 'info';
    this.log('info', `Response sent: ${res.statusCode} ${this.getStatusText(res.statusCode)}`);
    this.log('debug', responseInfo);
    this.log('info', `=== REQUEST END [${requestId}] === (${duration}ms)`);
    this.log('info', '======================================================');
  }

  // Get HTTP status text
  getStatusText(statusCode) {
    const statusTexts = {
      200: 'OK', 201: 'Created', 204: 'No Content',
      301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified',
      400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 
      404: 'Not Found', 405: 'Method Not Allowed', 429: 'Too Many Requests',
      500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable'
    };
    return statusTexts[statusCode] || 'Unknown Status';
  }

  setupMiddleware() {
    // Configure CORS based on settings
    if (this.config.cors.enabled) {
      const corsOptions = {
        origin: this.config.cors.origin,
        methods: this.config.cors.methods,
        allowedHeaders: this.config.cors.allowedHeaders,
        credentials: this.config.cors.credentials
      };
      this.app.use(cors(corsOptions));
    }
    
    // Parse JSON bodies
    this.app.use(express.json({ limit: '50mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '50mb' }));

    // Management API endpoints - always need CORS for web interface
    this.app.get('/apixxx/scenarios', cors(), (req, res) => this.getScenarios(req, res));
    this.app.post('/apixxx/scenarios', cors(), (req, res) => this.updateScenarios(req, res));
    this.app.get('/apixxx/config', cors(), (req, res) => this.getConfig(req, res));
    this.app.post('/apixxx/config', cors(), (req, res) => this.updateConfig(req, res));
    this.app.get('/apixxx/files', cors(), (req, res) => this.getScenarioFiles(req, res));
    this.app.post('/apixxx/rename-file', cors(), (req, res) => this.renameScenarioFile(req, res));
    this.app.delete('/apixxx/delete-file/:fileName', cors(), (req, res) => this.deleteScenarioFile(req, res));

    // Serve management interface
    this.app.get('/management', (req, res) => {
      res.sendFile(path.join(__dirname, 'management.html'));
    });

    // Main request handler - this should be last
    this.app.use('*', (req, res) => this.handleRequest(req, res));
  }

  async ensureScenariosDirectory() {
    try {
      await fs.mkdir(this.configPath, { recursive: true });
      this.log('info', `✅ Scenarios directory ensured: ${this.configPath}`);
    } catch (error) {
      this.log('error', '❌ Error creating scenarios directory:', { error: error.message });
      throw error;
    }
  }

  async ensureResponseFilesDirectory() {
    try {
      await fs.mkdir(this.config.responseFilesRoot, { recursive: true });
      this.log('info', `✅ Response files directory ensured: ${this.config.responseFilesRoot}`);
    } catch (error) {
      this.log('error', '❌ Error creating response files directory:', { error: error.message });
      // Don't throw error here - just log it as file responses might not be used
    }
  }

  async ensureLogFolder() {
    try {
      await fs.mkdir(this.config.logFolder, { recursive: true });
    } catch (error) {
      this.log('error', 'Error creating log folder:', { error: error.message });
    }
  }

  resolveFilePath(filePath) {
    // Security: Prevent directory traversal attacks
    const normalizedPath = path.normalize(filePath);
    if (normalizedPath.includes('..')) {
      throw new Error('Directory traversal not allowed in file paths');
    }

    // If filePath is absolute, use it as-is (but still check for traversal)
    if (path.isAbsolute(normalizedPath)) {
      return normalizedPath;
    }

    // If filePath is relative, resolve it relative to responseFilesRoot
    const resolvedPath = path.resolve(this.config.responseFilesRoot, normalizedPath);
    
    // Ensure the resolved path is still within responseFilesRoot
    const responseFilesRootResolved = path.resolve(this.config.responseFilesRoot);
    if (!resolvedPath.startsWith(responseFilesRootResolved)) {
      throw new Error('File path must be within the configured response files root directory');
    }

    return resolvedPath;
  }

  async loadScenarios() {
    try {
      await this.ensureScenariosDirectory();
      await this.ensureResponseFilesDirectory();
      
      // Get all JSON files in the scenarios directory
      const files = await fs.readdir(this.configPath);
      const jsonFiles = files.filter(file => file.endsWith('.json'));
      
      if (jsonFiles.length === 0) {
        this.log('warn', '⚠️  No scenario files found, creating default.json');
        await this.createDefaultScenarioFile();
        jsonFiles.push('default.json');
      }

      this.scenarios = {};
      this.scenarioFiles = {};
      const duplicateEndpoints = new Map();

      this.log('info', `📁 Loading scenarios from ${jsonFiles.length} file(s):`);
      
      for (const file of jsonFiles) {
        const filePath = path.join(this.configPath, file);
        const fileName = path.basename(file, '.json');
        
        try {
          const data = await fs.readFile(filePath, 'utf8');
          const fileScenarios = JSON.parse(data);
          
          this.log('info', `   📄 ${file}: ${Object.keys(fileScenarios).length} endpoint(s)`);
          
          // Check for duplicate endpoints
          Object.keys(fileScenarios).forEach(endpointKey => {
            if (this.scenarios[endpointKey]) {
              const existingFile = duplicateEndpoints.get(endpointKey);
              const error = `Duplicate endpoint "${endpointKey}" found in "${file}" and "${existingFile}"`;
              duplicateEndpoints.set(endpointKey, file);
              throw new Error(error);
            }
            duplicateEndpoints.set(endpointKey, file);
          });

          // Merge scenarios and track file associations
          Object.entries(fileScenarios).forEach(([endpointKey, config]) => {
            this.scenarios[endpointKey] = config;
            this.scenarioFiles[endpointKey] = fileName;
            
            // Add source file to each scenario for tracking
            if (config.scenarios) {
              config.scenarios.forEach(scenario => {
                scenario.sourceFile = fileName;
              });
            }
          });
          
        } catch (error) {
          if (error.message.includes('Duplicate endpoint')) {
            this.log('error', `❌ ${error.message}`);
            throw error;
          }
          this.log('error', `❌ Error loading ${file}:`, { error: error.message });
          throw new Error(`Failed to load scenarios from ${file}: ${error.message}`);
        }
      }
      
      const totalEndpoints = Object.keys(this.scenarios).length;
      this.log('info', `✅ Successfully loaded ${totalEndpoints} unique endpoint(s) from ${jsonFiles.length} file(s)`);
      
    } catch (error) {
      this.log('error', '❌ Critical error loading scenarios:', { error: error.message });
      process.exit(1);
    }
  }

  async createDefaultScenarioFile() {
    const defaultScenarios = {
      "GET /api/health": {
        "scenarios": [
          {
            "name": "Healthy Response",
            "actionType": "mock",
            "filters": [],
            "response": {
              "statusCode": 200,
              "headers": {
                "Content-Type": "text/plain"
              },
              "bodyType": "text",
              "body": "OK - Server is healthy"
            }
          }
        ],
        "defaultBehavior": "first",
        "logicOperator": "and"
      }
    };

    const defaultFilePath = path.join(this.configPath, 'default.json');
    await fs.writeFile(defaultFilePath, JSON.stringify(defaultScenarios, null, 2));
    this.log('info', '✅ Created default scenario file: default.json');
  }

  async saveScenarios() {
    try {
      // Group scenarios by their source files
      const fileGroups = {};
      
      Object.entries(this.scenarios).forEach(([endpointKey, config]) => {
        const fileName = this.scenarioFiles[endpointKey] || 'default';
        if (!fileGroups[fileName]) {
          fileGroups[fileName] = {};
        }
        
        // Clean up scenarios - remove sourceFile property before saving
        const cleanConfig = { ...config };
        if (cleanConfig.scenarios) {
          cleanConfig.scenarios = cleanConfig.scenarios.map(scenario => {
            const { sourceFile, ...cleanScenario } = scenario;
            return cleanScenario;
          });
        }
        
        fileGroups[fileName][endpointKey] = cleanConfig;
      });

      // Save each file group
      for (const [fileName, scenarios] of Object.entries(fileGroups)) {
        const filePath = path.join(this.configPath, `${fileName}.json`);
        await fs.writeFile(filePath, JSON.stringify(scenarios, null, 2));
        this.log('info', `💾 Saved ${Object.keys(scenarios).length} scenario(s) to ${fileName}.json`);
      }
      
    } catch (error) {
      this.log('error', '❌ Error saving scenarios:', { error: error.message });
      throw error;
    }
  }

  maskSensitiveData(content) {
    let maskedContent = content;
    this.config.maskSecrets.forEach(({ pattern, replacement }) => {
      maskedContent = maskedContent.replace(pattern, replacement);
    });
    return maskedContent;
  }

  matchesFilter(req, filter) {
    const { type, field, operator, value } = filter;

    let actualValue;
    switch (type) {
      case 'query':
        actualValue = req.query[field];
        break;
      case 'header':
        actualValue = req.headers[field?.toLowerCase()];
        break;
      case 'url':
        actualValue = req.originalUrl;
        break;
      case 'body':
        // Handle different body filter scenarios
        if (field) {
          // Filter specific field in body (for JSON objects)
          try {
            const body = req.body;
            if (typeof body === 'object' && body !== null) {
              actualValue = this.getNestedValue(body, field);
            } else {
              actualValue = body;
            }
          } catch (e) {
            actualValue = req.body;
          }
        } else {
          // Filter entire body (converted to string for comparison)
          actualValue = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
        }
        break;
      default:
        return false;
    }

    if (actualValue === undefined || actualValue === null) {
      return false;
    }

    actualValue = String(actualValue);
    const filterValue = String(value);

    switch (operator) {
      case 'equals':
        return actualValue === filterValue;
      case 'not_equals':
        return actualValue !== filterValue;
      case 'contains':
        return actualValue.includes(filterValue);
      case 'not_contains':
        return !actualValue.includes(filterValue);
      case 'regex':
        try {
          const regex = new RegExp(filterValue);
          return regex.test(actualValue);
        } catch (e) {
          this.log('error', `Invalid regex pattern: ${filterValue}`, { error: e.message });
          return false;
        }
      case 'not_regex':
        try {
          const regex = new RegExp(filterValue);
          return !regex.test(actualValue);
        } catch (e) {
          this.log('error', `Invalid regex pattern: ${filterValue}`, { error: e.message });
          return false;
        }
      default:
        return false;
    }
  }

  // Helper method to get nested object values using dot notation
  getNestedValue(obj, path) {
    return path.split('.').reduce((current, key) => {
      return current && current[key] !== undefined ? current[key] : undefined;
    }, obj);
  }

  findMatchingScenario(req) {
    // Use originalUrl and strip query parameters to get the path
    const endpoint = req.originalUrl.split('?')[0];
    const method = req.method.toUpperCase();
    const key = `${method} ${endpoint}`;

    // Step 1: Try exact match first (highest priority)
    let endpointScenarios = this.scenarios[key];
    let matchedWildcardKey = null;
    
    // Step 2: Try wildcard matching only if no exact match (lowest priority)
    if (!endpointScenarios) {
      const wildcardKeys = Object.keys(this.scenarios).filter(k => k.includes('*'));
      
      // Sort wildcard keys by specificity (more specific patterns first)
      const sortedWildcardKeys = wildcardKeys.sort((a, b) => {
        const aPath = a.split(' ', 2)[1];
        const bPath = b.split(' ', 2)[1];
        // Count non-wildcard characters (more specific = higher count)
        const aSpecificity = aPath.replace(/\*/g, '').length;
        const bSpecificity = bPath.replace(/\*/g, '').length;
        return bSpecificity - aSpecificity; // Higher specificity first
      });
      
      for (const wildcardKey of sortedWildcardKeys) {
        const [wildcardMethod, wildcardPath] = wildcardKey.split(' ', 2);
        if (wildcardMethod === method || wildcardMethod === '*') {
          const regexPattern = wildcardPath.replace(/\*/g, '(.*)');
          const regex = new RegExp(`^${regexPattern}$`);
          if (regex.test(endpoint)) {
            endpointScenarios = this.scenarios[wildcardKey];
            matchedWildcardKey = wildcardKey;
            this.log('info', `🎯 Wildcard match: ${endpoint} matched pattern ${wildcardKey}`);
            break;
          }
        }
      }
    } else {
      this.log('info', `🎯 Exact match: ${key}`);
    }

    if (!endpointScenarios?.scenarios?.length) {
      return null;
    }

    const { scenarios, defaultBehavior = 'first', logicOperator = 'and' } = endpointScenarios;

    // Find scenarios with matching filters
    const matchingScenarios = scenarios.filter(scenario => {
      if (!scenario.filters?.length) return false;

      const filterResults = scenario.filters.map(filter => this.matchesFilter(req, filter));
      
      return logicOperator === 'and' 
        ? filterResults.every(result => result)
        : filterResults.some(result => result);
    });

    if (matchingScenarios.length > 0) {
      // Add wildcard info to the matched scenario for proxy path rewriting
      const selectedScenario = { ...matchingScenarios[0] };
      if (matchedWildcardKey) {
        selectedScenario._wildcardInfo = {
          originalKey: matchedWildcardKey,
          requestPath: endpoint
        };
      }
      return selectedScenario;
    }

    // No matching filters, use scenarios without filters
    const noFilterScenarios = scenarios.filter(scenario => !scenario.filters?.length);
    
    if (noFilterScenarios.length === 0) {
      return null;
    }

    let selectedScenario;
    
    if (defaultBehavior === 'round_robin') {
      // Simple round-robin implementation
      if (!endpointScenarios.roundRobinIndex) {
        endpointScenarios.roundRobinIndex = 0;
      }
      selectedScenario = { ...noFilterScenarios[endpointScenarios.roundRobinIndex] };
      endpointScenarios.roundRobinIndex = (endpointScenarios.roundRobinIndex + 1) % noFilterScenarios.length;
    } else if (defaultBehavior && defaultBehavior !== 'first') {
      // Find scenario by name
      const namedScenario = noFilterScenarios.find(scenario => scenario.name === defaultBehavior);
      selectedScenario = { ...(namedScenario || noFilterScenarios[0]) };
    } else {
      // Default to first
      selectedScenario = { ...noFilterScenarios[0] };
    }

    // Add wildcard info to the selected scenario for proxy path rewriting
    if (matchedWildcardKey) {
      selectedScenario._wildcardInfo = {
        originalKey: matchedWildcardKey,
        requestPath: endpoint
      };
    }

    return selectedScenario;
  }

  async handleRequest(req, res) {
    const requestInfo = this.logRequestStart(req);
    
    try {
      const scenario = this.findMatchingScenario(req);
      
      if (!scenario) {
        const errorResponse = { error: 'No matching scenario found' };
        res.status(404).json(errorResponse);
        this.logRequestEnd(req, res, null, errorResponse);
        return;
      }

      if (scenario.actionType === 'proxy') {
        await this.handleProxyRequest(req, res, scenario);
      } else {
        await this.handleMockRequest(req, res, scenario);
      }
    } catch (error) {
      this.log('error', 'Error handling request:', { error: error.message, stack: error.stack });
      const errorResponse = { error: 'Internal server error' };
      res.status(500).json(errorResponse);
      this.logRequestEnd(req, res, null, errorResponse);
    }
  }

  // Native HTTP proxy implementation without external dependencies
  async handleProxyRequest(req, res, scenario) {
    const { destinationUrl, useSystemProxy } = scenario.response;
    
    if (!destinationUrl) {
      const errorResponse = { error: 'No destination URL configured for proxy' };
      res.status(500).json(errorResponse);
      this.logRequestEnd(req, res, scenario, errorResponse);
      return;
    }

    try {
      const targetUrl = new URL(destinationUrl);
      let requestPath = req.originalUrl;
      
      // Handle wildcard path rewriting
      if (scenario._wildcardInfo) {
        const { originalKey, requestPath: originalPath } = scenario._wildcardInfo;
        const [, wildcardPattern] = originalKey.split(' ', 2);
        
        // Extract the wildcard part from the request path
        const wildcardPrefix = wildcardPattern.replace('*', '');
        if (originalPath.startsWith(wildcardPrefix)) {
          const remainingPath = originalPath.substring(wildcardPrefix.length - 1);
          requestPath = remainingPath;
          
          this.log('info', `🔄 Wildcard proxy rewrite: ${originalPath} -> ${destinationUrl}/${remainingPath}`);
        }
      } else {
        //if not wildcard
        requestPath = '';
      }
      
      // Build the final proxy URL
      const proxyUrl = `${targetUrl.protocol}//${targetUrl.host}${targetUrl.pathname}${requestPath}`;
      const parsedUrl = new URL(proxyUrl);
      
      this.log('info', `🔗 Proxying request to: ${proxyUrl}`);
      this.log('debug', {
        originalPath: req.originalUrl,
        requestPath,
        targetUrl: destinationUrl,
        finalUrl: proxyUrl,
        useSystemProxy,
        wildcardRewrite: !!scenario._wildcardInfo
      });
      
      // Check if we need to use an HTTP proxy
      if (useSystemProxy && this.config.httpProxy.enabled) {
        await this.handleHttpProxyRequest(req, res, scenario, parsedUrl);
      } else {
        await this.handleDirectProxyRequest(req, res, scenario, parsedUrl);
      }
    } catch (error) {
      this.log('error', 'Error parsing proxy URL:', { 
        error: error.message, 
        target: destinationUrl,
        requestUrl: req.originalUrl
      });
      
      const errorResponse = { error: 'Invalid proxy configuration', details: error.message };
      res.status(400).json(errorResponse);
      this.logRequestEnd(req, res, scenario, errorResponse);
    }
  }

  // Handle direct proxy requests (no HTTP proxy)
  async handleDirectProxyRequest(req, res, scenario, parsedUrl) {
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: req.method,
      headers: {
        ...req.headers,
        host: parsedUrl.host
      }
    };

    // Remove connection headers that shouldn't be forwarded
    delete options.headers.connection;
    delete options.headers['proxy-connection'];
    delete options.headers['pragma'];
    delete options.headers['origin'];
    delete options.headers['referer'];

    this.log('debug', 'Direct proxy request options:', { 
      options: {
        ...options,
        headers: this.sanitizeHeaders(options.headers)
      }
    });

    const protocol = parsedUrl.protocol === 'https:' ? https : http;
    
    const proxyReq = protocol.request(options, (proxyRes) => {
      this.handleProxyResponse(req, res, scenario, proxyRes, 'direct');
    });

    this.setupProxyRequest(req, res, proxyReq, scenario, 'direct');
  }

  // Handle requests through HTTP proxy
  async handleHttpProxyRequest(req, res, scenario, parsedUrl) {
    const httpProxyConfig = this.config.httpProxy;
    const proxyHost = httpProxyConfig.host;
    const proxyPort = httpProxyConfig.port || 8080;
    
    const options = {
      hostname: proxyHost,
      port: proxyPort,
      path: parsedUrl.href, // Full URL for HTTP proxy
      method: req.method,
      headers: {
        ...req.headers,
        host: parsedUrl.host
      }
    };

    // Add proxy authentication if provided
    if (httpProxyConfig.username && httpProxyConfig.password) {
      const auth = Buffer.from(`${httpProxyConfig.username}:${httpProxyConfig.password}`).toString('base64');
      options.headers['proxy-authorization'] = `Basic ${auth}`;
      this.log('debug', 'Added proxy authentication');
    }

    // Remove connection headers that shouldn't be forwarded
    delete options.headers.connection;
    delete options.headers['proxy-connection'];
    delete options.headers['pragma'];
    delete options.headers['origin'];
    delete options.headers['referer'];

    this.log('debug', 'HTTP proxy request options:', { 
      proxyHost: `${proxyHost}:${proxyPort}`,
      targetUrl: parsedUrl.href,
      hasAuth: !!(httpProxyConfig.username && httpProxyConfig.password),
      options: {
        ...options,
        headers: this.sanitizeHeaders(options.headers)
      }
    });

    // For HTTPS targets through HTTP proxy, we need to handle CONNECT method
    if (parsedUrl.protocol === 'https:') {
      this.handleHttpsProxyRequest(req, res, scenario, parsedUrl, options);
    } else {
      // Direct HTTP request through proxy
      const proxyReq = http.request(options, (proxyRes) => {
        this.handleProxyResponse(req, res, scenario, proxyRes, 'http-proxy');
      });

      this.setupProxyRequest(req, res, proxyReq, scenario, 'http-proxy');
    }
  }

  // Handle HTTPS requests through HTTP proxy using CONNECT method
  async handleHttpsProxyRequest(req, res, scenario, parsedUrl, proxyOptions) {
    const connectOptions = {
      ...proxyOptions,
      method: 'CONNECT',
      path: `${parsedUrl.hostname}:${parsedUrl.port || 443}`
    };

    this.log('debug', 'HTTPS proxy CONNECT request:', { 
      connectPath: connectOptions.path,
      proxyHost: `${connectOptions.hostname}:${connectOptions.port}`
    });

    const connectReq = http.request(connectOptions);
    
    connectReq.on('connect', (connectRes, socket, head) => {
      this.log('info', `Proxy CONNECT response: ${connectRes.statusCode}`);
      this.log('debug', {
        statusCode: connectRes.statusCode,
        headers: connectRes.headers
      });
      
      if (connectRes.statusCode !== 200) {
        this.log('error', 'Proxy CONNECT failed:', { 
          statusCode: connectRes.statusCode,
          statusMessage: connectRes.statusMessage,
          headers: connectRes.headers
        });
        
        const errorResponse = { 
          error: 'Proxy Connection Failed', 
          statusCode: connectRes.statusCode,
          statusMessage: connectRes.statusMessage
        };
        res.status(502).json(errorResponse);
        this.logRequestEnd(req, res, scenario, errorResponse, {
          proxyDetails: {
            connectStatus: connectRes.statusCode,
            error: 'CONNECT failed',
            proxyType: 'https-proxy'
          }
        });
        return;
      }

      // Now make the HTTPS request through the tunnel
      const httpsOptions = {
        socket: socket,
        path: parsedUrl.pathname + parsedUrl.search,
        method: req.method,
        headers: {
          ...req.headers,
          host: parsedUrl.host
        }
      };

      delete httpsOptions.headers.connection;
      delete httpsOptions.headers['proxy-connection'];
      delete httpsOptions.headers['pragma'];
      delete httpsOptions.headers['origin'];
      delete httpsOptions.headers['referer'];

      this.log('debug', 'HTTPS request through tunnel:', {
        path: httpsOptions.path,
        method: httpsOptions.method,
        headers: this.sanitizeHeaders(httpsOptions.headers)
      });

      const httpsReq = https.request(httpsOptions, (httpsRes) => {
        this.handleProxyResponse(req, res, scenario, httpsRes, 'https-proxy');
      });

      this.setupProxyRequest(req, res, httpsReq, scenario, 'https-proxy');
    });

    connectReq.on('error', (err) => {
      this.log('error', 'Proxy CONNECT error:', { 
        error: err.message, 
        code: err.code,
        stack: err.stack
      });
      
      const errorResponse = { 
        error: 'Proxy Connection Error', 
        details: err.message,
        code: err.code
      };
      res.status(502).json(errorResponse);
      this.logRequestEnd(req, res, scenario, errorResponse, {
        proxyDetails: {
          error: err.message,
          proxyType: 'https-proxy'
        }
      });
    });

    connectReq.end();
  }

  // Common proxy response handler
  handleProxyResponse(req, res, scenario, proxyRes, proxyType) {
    this.log('info', `Proxy response received (${proxyType}):`);
    this.log('debug', {
      statusCode: proxyRes.statusCode,
      statusMessage: proxyRes.statusMessage,
      headers: proxyRes.headers,
      proxyType
    });

    // Log 403 errors with more details
    if (proxyRes.statusCode === 403) {
      this.log('error', '403 Forbidden received from target server:', {
        targetUrl: scenario.response.destinationUrl,
        requestPath: req.originalUrl,
        requestHeaders: this.sanitizeHeaders(req.headers),
        responseHeaders: proxyRes.headers,
        proxyType,
        userAgent: req.headers['user-agent'],
        referer: req.headers.referer,
        clientIP: req.connection.remoteAddress
      });
    }

    // Set CORS headers if enabled
    if (this.config.cors.enabled) {
      res.setHeader('Access-Control-Allow-Origin', this.config.cors.origin);
      res.setHeader('Access-Control-Allow-Methods', this.config.cors.methods.join(', '));
      res.setHeader('Access-Control-Allow-Headers', this.config.cors.allowedHeaders.join(', '));
      if (this.config.cors.credentials) {
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
    }

    // Forward response headers
    Object.keys(proxyRes.headers).forEach(key => {
      res.setHeader(key, proxyRes.headers[key]);
    });

    res.writeHead(proxyRes.statusCode);

    // Collect response data for logging
    let responseBody = '';
    proxyRes.on('data', (chunk) => {
      responseBody += chunk;
      res.write(chunk);
    });

    proxyRes.on('end', () => {
      res.end();
      
      // Log the completed proxy response
      this.logRequestEnd(req, res, scenario, responseBody, {
        proxyDetails: {
          destination: scenario.response.destinationUrl,
          originalPath: req.originalUrl,
          proxyStatus: proxyRes.statusCode,
          proxyHeaders: proxyRes.headers,
          useSystemProxy: scenario.response.useSystemProxy,
          wildcardRewrite: !!scenario._wildcardInfo,
          proxyType
        }
      });
    });
  }

  // Common proxy request setup
  setupProxyRequest(req, res, proxyReq, scenario, proxyType) {
    proxyReq.on('error', (err) => {
      this.log('error', `Proxy request error (${proxyType}):`, { 
        error: err.message, 
        code: err.code,
        stack: this.config.logLevel === 'debug' ? err.stack : undefined,
        proxyType
      });
      
      const errorResponse = { 
        error: 'Bad Gateway', 
        details: err.message,
        code: err.code,
        proxyType
      };
      
      if (!res.headersSent) {
        res.status(502).json(errorResponse);
      }
      
      this.logRequestEnd(req, res, scenario, errorResponse, { 
        proxyDetails: {
          error: err.message, 
          proxyType 
        }
      });
    });

    // Forward request body for POST/PUT/PATCH requests
    if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
      this.log('debug', `Forwarding request body for ${req.method} request`);
      
      // For Express.js, the body is already parsed, so we need to stringify it back
      if (req.body && Object.keys(req.body).length > 0) {
        const bodyData = JSON.stringify(req.body);
        proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
        proxyReq.write(bodyData);
      }
      proxyReq.end();
    } else {
      proxyReq.end();
    }
  }

  async handleMockRequest(req, res, scenario) {
    const { statusCode = 200, headers = {}, bodyType = 'json', body, filePath } = scenario.response;

    // Set response headers
    Object.entries(headers).forEach(([key, value]) => {
      res.setHeader(key, value);
    });

    // Set status code
    res.status(statusCode);

    let responseData;

    if (bodyType === 'file' && filePath) {
      try {
        // Resolve file path using the configured response files root
        const resolvedFilePath = this.resolveFilePath(filePath);
        
        this.log('info', `📁 Reading file response: ${filePath} -> ${resolvedFilePath}`);
        responseData = await fs.readFile(resolvedFilePath, 'utf8');
        
        const ext = path.extname(resolvedFilePath).toLowerCase();
        if (ext === '.json') {
          res.setHeader('Content-Type', 'application/json');
        } else if (ext === '.html') {
          res.setHeader('Content-Type', 'text/html');
        } else if (ext === '.xml') {
          res.setHeader('Content-Type', 'application/xml');
        } else if (ext === '.txt') {
          res.setHeader('Content-Type', 'text/plain');
        } else if (ext === '.css') {
          res.setHeader('Content-Type', 'text/css');
        } else if (ext === '.js') {
          res.setHeader('Content-Type', 'application/javascript');
        } else {
          res.setHeader('Content-Type', 'text/plain');
        }
        res.send(responseData);
      } catch (error) {
        this.log('error', `❌ Error reading file response: ${filePath}`, { error: error.message });
        let errorResponse;
        
        if (error.message.includes('Directory traversal') || error.message.includes('within the configured')) {
          errorResponse = { error: 'Security violation: Invalid file path', filePath };
          res.status(403).json(errorResponse);
        } else if (error.code === 'ENOENT') {
          errorResponse = { error: 'File not found', filePath, resolvedPath: this.resolveFilePath(filePath) };
          res.status(404).json(errorResponse);
        } else {
          errorResponse = { error: 'File read error', filePath, details: error.message };
          res.status(500).json(errorResponse);
        }
        responseData = errorResponse;
      }
    } else {
      responseData = body;
      if (bodyType === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.json(responseData);
      } else if (bodyType === 'html') {
        res.setHeader('Content-Type', 'text/html');
        res.send(responseData);
      } else {
        res.setHeader('Content-Type', 'text/plain');
        res.send(responseData);
      }
    }

    this.logRequestEnd(req, res, scenario, responseData);
  }

  // Management API endpoints
  async getScenarios(req, res) {
    // Include file information in the response
    const scenariosWithFiles = {};
    Object.entries(this.scenarios).forEach(([key, config]) => {
      scenariosWithFiles[key] = {
        ...config,
        sourceFile: this.scenarioFiles[key] || 'default'
      };
    });
    res.json(scenariosWithFiles);
  }

  async updateScenarios(req, res) {
    try {
      const newScenarios = req.body;
      
      // Extract file assignments and clean scenarios
      this.scenarios = {};
      this.scenarioFiles = {};
      
      Object.entries(newScenarios).forEach(([key, config]) => {
        const { sourceFile, ...cleanConfig } = config;
        this.scenarios[key] = cleanConfig;
        this.scenarioFiles[key] = sourceFile || 'default';
      });
      
      await this.saveScenarios();
      res.json({ success: true, message: 'Scenarios updated successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update scenarios', details: error.message });
    }
  }

  async getConfig(req, res) {
    res.json(this.config);
  }

  async updateConfig(req, res) {
    try {
      this.config = { ...this.config, ...req.body };
      res.json({ success: true, message: 'Configuration updated successfully' });
    } catch (error) {
      res.status(500).json({ error: 'Failed to update configuration', details: error.message });
    }
  }

  async getScenarioFiles(req, res) {
    try {
      const files = await fs.readdir(this.configPath);
      const jsonFiles = files.filter(file => file.endsWith('.json'))
        .map(file => path.basename(file, '.json'));
      
      res.json({ 
        files: jsonFiles,
        defaultFile: 'default'
      });
    } catch (error) {
      res.status(500).json({ error: 'Failed to get scenario files', details: error.message });
    }
  }

  async renameScenarioFile(req, res) {
    try {
      const { oldFileName, newFileName } = req.body;
      
      if (!oldFileName || !newFileName) {
        return res.status(400).json({ error: 'Both oldFileName and newFileName are required' });
      }

      // Validate new filename
      if (!/^[a-zA-Z0-9_-]+$/.test(newFileName)) {
        return res.status(400).json({ error: 'File name can only contain letters, numbers, hyphens, and underscores' });
      }

      // Don't allow renaming default file
      if (oldFileName === 'default') {
        return res.status(400).json({ error: 'Cannot rename the default file' });
      }

      const oldFilePath = path.join(this.configPath, `${oldFileName}.json`);
      const newFilePath = path.join(this.configPath, `${newFileName}.json`);

      // Check if old file exists
      try {
        await fs.access(oldFilePath);
      } catch (error) {
        return res.status(404).json({ error: `File ${oldFileName}.json not found` });
      }

      // Check if new file already exists
      try {
        await fs.access(newFilePath);
        return res.status(409).json({ error: `File ${newFileName}.json already exists` });
      } catch (error) {
        // Good, new file doesn't exist
      }

      // Rename the file
      await fs.rename(oldFilePath, newFilePath);

      // Update internal tracking
      Object.entries(this.scenarios).forEach(([endpointKey, config]) => {
        if (this.scenarioFiles[endpointKey] === oldFileName) {
          this.scenarioFiles[endpointKey] = newFileName;
        }
      });

      this.log('info', `✅ Renamed scenario file: ${oldFileName}.json → ${newFileName}.json`);
      res.json({ 
        success: true, 
        message: `File renamed from ${oldFileName}.json to ${newFileName}.json`,
        oldFileName,
        newFileName
      });

    } catch (error) {
      this.log('error', '❌ Error renaming scenario file:', { error: error.message });
      res.status(500).json({ error: 'Failed to rename file', details: error.message });
    }
  }

  async deleteScenarioFile(req, res) {
    try {
      const { fileName } = req.params;
      
      if (!fileName) {
        return res.status(400).json({ error: 'fileName is required' });
      }

      // Don't allow deleting default file
      if (fileName === 'default') {
        return res.status(400).json({ error: 'Cannot delete the default file' });
      }

      const filePath = path.join(this.configPath, `${fileName}.json`);

      // Check if file exists
      try {
        await fs.access(filePath);
      } catch (error) {
        return res.status(404).json({ error: `File ${fileName}.json not found` });
      }

      // Count endpoints that will be removed
      const endpointsToRemove = [];
      Object.entries(this.scenarios).forEach(([endpointKey, config]) => {
        if (this.scenarioFiles[endpointKey] === fileName) {
          endpointsToRemove.push(endpointKey);
        }
      });

      // Remove the file
      await fs.unlink(filePath);

      // Remove endpoints from memory
      endpointsToRemove.forEach(endpointKey => {
        delete this.scenarios[endpointKey];
        delete this.scenarioFiles[endpointKey];
      });

      this.log('info', `✅ Deleted scenario file: ${fileName}.json (removed ${endpointsToRemove.length} endpoints)`);
      res.json({ 
        success: true, 
        message: `File ${fileName}.json deleted successfully`,
        fileName,
        removedEndpoints: endpointsToRemove.length
      });

    } catch (error) {
      this.log('error', '❌ Error deleting scenario file:', { error: error.message });
      res.status(500).json({ error: 'Failed to delete file', details: error.message });
    }
  }

  // Get server statistics
  getServerStats() {
    return {
      uptime: process.uptime(),
      memoryUsage: process.memoryUsage(),
      pid: process.pid,
      platform: process.platform,
      nodeVersion: process.version,
      scenarios: {
        total: Object.keys(this.scenarios).length,
        files: [...new Set(Object.values(this.scenarioFiles))].length
      }
    };
  }

  start() {
    // Enhanced error handling
    process.on('uncaughtException', (error) => {
      this.log('error', '💥 Uncaught Exception:', { 
        error: error.message, 
        stack: error.stack 
      });
      process.exit(1);
    });

    process.on('unhandledRejection', (reason, promise) => {
      this.log('error', '💥 Unhandled Rejection:', { 
        reason: reason?.toString(), 
        promise: promise?.toString() 
      });
    });

    // Graceful shutdown
    process.on('SIGINT', () => {
      this.log('info', '🛑 Shutdown signal received...');
      this.log('info', '📊 Server statistics:', this.getServerStats());
      
      process.exit(0);
    });

    this.app.listen(this.config.port, () => {
      this.log('info', '='.repeat(60));
      this.log('info', `🚀 Proxy/Mock Server running on port ${this.config.port}`);
      this.log('info', `📊 Management interface: http://localhost:${this.config.port}/management`);
      this.log('info', `📁 Scenarios directory: ${this.configPath}`);
      this.log('info', `📂 Response files root: ${this.config.responseFilesRoot}`);
      this.log('info', `📝 Log folder: ${this.config.logFolder}`);
      this.log('info', `📊 Log level: ${this.config.logLevel}`);
      
      // Log loaded scenarios summary
      const fileCount = Object.keys(this.scenarioFiles).length;
      const uniqueFiles = [...new Set(Object.values(this.scenarioFiles))];
      this.log('info', `📋 Loaded ${fileCount} endpoint(s) from ${uniqueFiles.length} file(s): ${uniqueFiles.join(', ')}`);
      
      // Log CORS configuration
      if (this.config.cors.enabled) {
        this.log('info', `🌐 CORS: Enabled`);
        this.log('info', `   Origins: ${Array.isArray(this.config.cors.origin) ? this.config.cors.origin.join(', ') : this.config.cors.origin}`);
        this.log('info', `   Methods: ${this.config.cors.methods.join(', ')}`);
        this.log('info', `   Credentials: ${this.config.cors.credentials ? 'Allowed' : 'Not allowed'}`);
      } else {
        this.log('info', `🌐 CORS: Disabled`);
      }
      
      // Log HTTP proxy configuration if enabled
      if (this.config.httpProxy.enabled) {
        const proxyInfo = `${this.config.httpProxy.protocol}://${this.config.httpProxy.host}:${this.config.httpProxy.port}`;
        const authInfo = this.config.httpProxy.username ? ' (with authentication)' : ' (no authentication)';
        this.log('info', `🔗 HTTP Proxy: ${proxyInfo}${authInfo}`);
      } else {
        this.log('info', `🔗 HTTP Proxy: Disabled`);
      }
      this.log('info', '='.repeat(60));
    });
  }
}

// Usage
if (require.main === module) {
  // Allow scenarios directory to be passed as command line argument
  const scenariosDir = process.argv[2] || './scenarios-db';
  
  console.log(`🗂️  Using scenarios directory: ${scenariosDir}`);
  
  const server = new ProxyMockServer(scenariosDir, {
    port: process.env.PORT || 3001,
    logFolder: process.env.LOG_FOLDER || './logs',
    responseFilesRoot: process.env.RESPONSE_FILES_ROOT || './response-files',
    enableConsoleLog: process.env.ENABLE_CONSOLE_LOG !== 'false',
    enableFileLog: process.env.ENABLE_FILE_LOG !== 'false',
    logDetails: process.env.LOG_DETAILS !== 'false',
    logProxyDetails: process.env.LOG_PROXY_DETAILS !== 'false',
    logLevel: process.env.LOG_LEVEL || 'info',
    cors: {
      enabled: process.env.CORS_ENABLED !== 'false',
      origin: process.env.CORS_ORIGIN || '*',
      methods: process.env.CORS_METHODS ? process.env.CORS_METHODS.split(',') : ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: process.env.CORS_ALLOWED_HEADERS ? process.env.CORS_ALLOWED_HEADERS.split(',') : ['Content-Type', 'Authorization', 'X-Requested-With'],
      credentials: process.env.CORS_CREDENTIALS !== 'false'
    },
    httpProxy: {
      enabled: process.env.HTTP_PROXY_ENABLED === 'true',
      host: process.env.HTTP_PROXY_HOST,
      port: process.env.HTTP_PROXY_PORT ? parseInt(process.env.HTTP_PROXY_PORT) : undefined,
      username: process.env.HTTP_PROXY_USERNAME,
      password: process.env.HTTP_PROXY_PASSWORD,
      protocol: process.env.HTTP_PROXY_PROTOCOL || 'http'
    }
  });
  
  server.start();
}

module.exports = ProxyMockServer;