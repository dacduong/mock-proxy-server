const express = require('express');
const httpProxy = require('http-proxy-middleware');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const HttpsProxyAgent = require('https-proxy-agent');
const HttpProxyAgent = require('http-proxy-agent');

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
    
    this.setupMiddleware();
    this.loadScenarios();
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
      console.log(`✅ Scenarios directory ensured: ${this.configPath}`);
    } catch (error) {
      console.error('❌ Error creating scenarios directory:', error);
      throw error;
    }
  }

  async ensureResponseFilesDirectory() {
    try {
      await fs.mkdir(this.config.responseFilesRoot, { recursive: true });
      console.log(`✅ Response files directory ensured: ${this.config.responseFilesRoot}`);
    } catch (error) {
      console.error('❌ Error creating response files directory:', error);
      // Don't throw error here - just log it as file responses might not be used
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
        console.log('⚠️  No scenario files found, creating default.json');
        await this.createDefaultScenarioFile();
        jsonFiles.push('default.json');
      }

      this.scenarios = {};
      this.scenarioFiles = {};
      const duplicateEndpoints = new Map();

      console.log(`📁 Loading scenarios from ${jsonFiles.length} file(s):`);
      
      for (const file of jsonFiles) {
        const filePath = path.join(this.configPath, file);
        const fileName = path.basename(file, '.json');
        
        try {
          const data = await fs.readFile(filePath, 'utf8');
          const fileScenarios = JSON.parse(data);
          
          console.log(`   📄 ${file}: ${Object.keys(fileScenarios).length} endpoint(s)`);
          
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
            console.error(`❌ ${error.message}`);
            throw error;
          }
          console.error(`❌ Error loading ${file}:`, error.message);
          throw new Error(`Failed to load scenarios from ${file}: ${error.message}`);
        }
      }
      
      const totalEndpoints = Object.keys(this.scenarios).length;
      console.log(`✅ Successfully loaded ${totalEndpoints} unique endpoint(s) from ${jsonFiles.length} file(s)`);
      
    } catch (error) {
      console.error('❌ Critical error loading scenarios:', error.message);
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
    console.log('✅ Created default scenario file: default.json');
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
        console.log(`💾 Saved ${Object.keys(scenarios).length} scenario(s) to ${fileName}.json`);
      }
      
    } catch (error) {
      console.error('❌ Error saving scenarios:', error);
      throw error;
    }
  }

  async ensureLogFolder() {
    try {
      await fs.mkdir(this.config.logFolder, { recursive: true });
    } catch (error) {
      console.error('Error creating log folder:', error);
    }
  }

  maskSensitiveData(content) {
    let maskedContent = content;
    this.config.maskSecrets.forEach(({ pattern, replacement }) => {
      maskedContent = maskedContent.replace(pattern, replacement);
    });
    return maskedContent;
  }

  async logRequest(req, res, scenario, responseData, additionalInfo = {}) {
    const timestamp = new Date().toISOString();
    const logEntry = {
      timestamp,
      method: req.method,
      url: req.originalUrl,
      headers: req.headers,
      query: req.query,
      body: req.body,
      scenario: scenario?.name || 'no-match',
      sourceFile: scenario?.sourceFile || 'unknown',
      response: {
        statusCode: res.statusCode,
        headers: res.getHeaders(),
        body: responseData
      },
      ...additionalInfo
    };

    const maskedLogEntry = {
      ...logEntry,
      headers: JSON.parse(this.maskSensitiveData(JSON.stringify(logEntry.headers))),
      body: JSON.parse(this.maskSensitiveData(JSON.stringify(logEntry.body))),
      response: {
        ...logEntry.response,
        headers: JSON.parse(this.maskSensitiveData(JSON.stringify(logEntry.response.headers))),
        body: this.maskSensitiveData(JSON.stringify(logEntry.response.body))
      }
    };

    // Console logging with detail levels
    if (this.config.enableConsoleLog) {
      console.log(`\n🔄 ${req.method} ${req.originalUrl}`);
      console.log(`📋 Scenario: ${scenario?.name || 'no-match'} (${scenario?.sourceFile || 'unknown'})`);
      console.log(`📤 Response: ${res.statusCode}`);
      console.log(`🕐 ${timestamp}`);
      
      if (this.config.logDetails) {
        console.log(`📨 Request Headers:`, JSON.stringify(maskedLogEntry.headers, null, 2));
        if (Object.keys(req.query).length > 0) {
          console.log(`❓ Query Params:`, req.query);
        }
        if (req.body && Object.keys(req.body).length > 0) {
          console.log(`📝 Request Body:`, JSON.stringify(maskedLogEntry.body, null, 2));
        }
        console.log(`📬 Response Headers:`, JSON.stringify(maskedLogEntry.response.headers, null, 2));
        const bodyStr = typeof responseData === 'string' ? responseData : JSON.stringify(responseData);
        console.log(`📋 Response Body:`, bodyStr.substring(0, 1000) + (bodyStr.length > 1000 ? '...' : ''));
      }

      // Log proxy details if present
      if (additionalInfo.proxyDetails) {
        const proxy = additionalInfo.proxyDetails;
        console.log(`🔗 Proxy Details:`);
        console.log(`   Destination: ${proxy.destination}`);
        if (proxy.originalPath && proxy.rewrittenPath) {
          console.log(`   Path Rewrite: ${proxy.originalPath} -> ${proxy.rewrittenPath}`);
        }
        if (proxy.useSystemProxy) {
          console.log(`   Via System Proxy: ${this.config.httpProxy.host}:${this.config.httpProxy.port}`);
        }
        if (proxy.wildcardRewrite) {
          console.log(`   Wildcard Rewrite: Yes`);
        }
        if (proxy.proxyStatus) {
          console.log(`   Proxy Status: ${proxy.proxyStatus}`);
        }
        if (proxy.error) {
          console.log(`   Proxy Error: ${proxy.error}`);
        }
      }
      
      console.log('======');
    }

    // File logging
    if (this.config.enableFileLog) {
      await this.ensureLogFolder();
      const logFileName = `${timestamp.split('T')[0]}.log`;
      const logFilePath = path.join(this.config.logFolder, logFileName);
      const logLine = JSON.stringify(maskedLogEntry) + '\n';
      
      try {
        await fs.appendFile(logFilePath, logLine);
      } catch (error) {
        console.error('Error writing to log file:', error);
      }
    }
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
          console.error(`Invalid regex pattern: ${filterValue}`, e);
          return false;
        }
      case 'not_regex':
        try {
          const regex = new RegExp(filterValue);
          return !regex.test(actualValue);
        } catch (e) {
          console.error(`Invalid regex pattern: ${filterValue}`, e);
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
            console.log(`🎯 Wildcard match: ${endpoint} matched pattern ${wildcardKey}`);
            break;
          }
        }
      }
    } else {
      console.log(`🎯 Exact match: ${key}`);
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
    try {
      const scenario = this.findMatchingScenario(req);
      
      if (!scenario) {
        const errorResponse = { error: 'No matching scenario found' };
        res.status(404).json(errorResponse);
        await this.logRequest(req, res, null, errorResponse);
        return;
      }

      if (scenario.actionType === 'proxy') {
        await this.handleProxyRequest(req, res, scenario);
      } else {
        await this.handleMockRequest(req, res, scenario);
      }
    } catch (error) {
      console.error('Error handling request:', error);
      const errorResponse = { error: 'Internal server error' };
      res.status(500).json(errorResponse);
      await this.logRequest(req, res, null, errorResponse);
    }
  }

  createProxyAgent() {
    const proxyConfig = this.config.httpProxy;
    
    if (!proxyConfig.enabled || !proxyConfig.host || !proxyConfig.port) {
      return null;
    }

    // Build proxy URL with authentication if provided
    let proxyUrl = `${proxyConfig.protocol}://`;
    
    if (proxyConfig.username && proxyConfig.password) {
      // URL encode username and password to handle special characters
      const encodedUsername = encodeURIComponent(proxyConfig.username);
      const encodedPassword = encodeURIComponent(proxyConfig.password);
      proxyUrl += `${encodedUsername}:${encodedPassword}@`;
    }
    
    proxyUrl += `${proxyConfig.host}:${proxyConfig.port}`;

    // Create appropriate proxy agent based on protocol
    if (proxyConfig.protocol === 'https') {
      return new HttpsProxyAgent(proxyUrl);
    } else {
      return new HttpProxyAgent(proxyUrl);
    }
  }

  async handleProxyRequest(req, res, scenario) {
    const { destinationUrl, useSystemProxy } = scenario.response;
    
    if (!destinationUrl) {
      const errorResponse = { error: 'No destination URL configured for proxy' };
      res.status(500).json(errorResponse);
      await this.logRequest(req, res, scenario, errorResponse);
      return;
    }

    // Handle wildcard path rewriting
    let targetUrl = destinationUrl;
    let pathRewrite = undefined;
    
    if (scenario._wildcardInfo) {
      const { originalKey, requestPath } = scenario._wildcardInfo;
      const [, wildcardPattern] = originalKey.split(' ', 2);
      
      // Extract the wildcard part from the request path
      const wildcardPrefix = wildcardPattern.replace('*', '');
      if (requestPath.startsWith(wildcardPrefix)) {
        const remainingPath = requestPath.substring(wildcardPrefix.length);
        // Set up path rewrite to strip the matched prefix
        pathRewrite = {
          [`^${wildcardPrefix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`]: ''
        };
        
        console.log(`🔄 Wildcard proxy rewrite: ${requestPath} -> ${destinationUrl}${remainingPath}`);
      }
    }

    // Create proxy configuration
    const proxyConfig = {
      target: targetUrl,
      changeOrigin: true,
      pathRewrite: pathRewrite,
      onProxyReq: (proxyReq, req, res) => {
        // Log outbound proxy request details
        if (this.config.enableConsoleLog) {
          console.log(`🔄 Proxy Request to: ${targetUrl}${proxyReq.path}`);
          console.log(`   Method: ${proxyReq.method}`);
          if (this.config.logProxyDetails) {
            console.log(`   Headers:`, JSON.stringify(proxyReq.getHeaders(), null, 2));
          }
        }
      },
      onProxyRes: async (proxyRes, req, res) => {
        let body = '';
        proxyRes.on('data', (chunk) => {
          body += chunk;
        });
        proxyRes.on('end', async () => {
          try {
            // Log proxy response details
            if (this.config.enableConsoleLog && this.config.logProxyDetails) {
              console.log(`📥 Proxy Response from: ${targetUrl}`);
              console.log(`   Status: ${proxyRes.statusCode}`);
              console.log(`   Headers:`, JSON.stringify(proxyRes.headers, null, 2));
              console.log(`   Body: ${body.substring(0, 500)}${body.length > 500 ? '...' : ''}`);
            }
            
            const responseData = body;
            await this.logRequest(req, res, scenario, responseData, {
              proxyDetails: {
                destination: targetUrl,
                originalPath: req.originalUrl,
                rewrittenPath: pathRewrite ? req.originalUrl.replace(Object.keys(pathRewrite)[0], pathRewrite[Object.keys(pathRewrite)[0]]) : req.originalUrl,
                proxyStatus: proxyRes.statusCode,
                proxyHeaders: proxyRes.headers,
                useSystemProxy: useSystemProxy,
                wildcardRewrite: !!scenario._wildcardInfo
              }
            });
          } catch (error) {
            console.error('Error in proxy response logging:', error);
          }
        });
      },
      onError: async (err, req, res) => {
        console.error('Proxy error:', err);
        const errorResponse = { error: 'Proxy error', details: err.message };
        res.status(502).json(errorResponse);
        await this.logRequest(req, res, scenario, errorResponse, {
          proxyDetails: {
            destination: targetUrl,
            originalPath: req.originalUrl,
            error: err.message,
            useSystemProxy: useSystemProxy,
            wildcardRewrite: !!scenario._wildcardInfo
          }
        });
      }
    };

    // Add HTTP proxy agent if configured and scenario requests it
    const proxyAgent = (useSystemProxy && this.config.httpProxy.enabled) ? this.createProxyAgent() : null;
    if (proxyAgent) {
      proxyConfig.agent = proxyAgent;
      console.log(`🌐 Using HTTP proxy: ${this.config.httpProxy.protocol}://${this.config.httpProxy.host}:${this.config.httpProxy.port} for ${targetUrl}`);
    }

    // Create and use proxy middleware
    const proxy = httpProxy.createProxyMiddleware(proxyConfig);
    proxy(req, res);
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
        
        console.log(`📁 Reading file response: ${filePath} -> ${resolvedFilePath}`);
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
        console.error(`❌ Error reading file response: ${filePath}`, error.message);
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

    await this.logRequest(req, res, scenario, responseData);
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

      console.log(`✅ Renamed scenario file: ${oldFileName}.json → ${newFileName}.json`);
      res.json({ 
        success: true, 
        message: `File renamed from ${oldFileName}.json to ${newFileName}.json`,
        oldFileName,
        newFileName
      });

    } catch (error) {
      console.error('❌ Error renaming scenario file:', error);
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

      console.log(`✅ Deleted scenario file: ${fileName}.json (removed ${endpointsToRemove.length} endpoints)`);
      res.json({ 
        success: true, 
        message: `File ${fileName}.json deleted successfully`,
        fileName,
        removedEndpoints: endpointsToRemove.length
      });

    } catch (error) {
      console.error('❌ Error deleting scenario file:', error);
      res.status(500).json({ error: 'Failed to delete file', details: error.message });
    }
  }

  start() {
    this.app.listen(this.config.port, () => {
      console.log(`🚀 Proxy/Mock Server running on port ${this.config.port}`);
      console.log(`📊 Management interface: http://localhost:${this.config.port}/management`);
      console.log(`📁 Scenarios directory: ${this.configPath}`);
      console.log(`📂 Response files root: ${this.config.responseFilesRoot}`);
      console.log(`📝 Log folder: ${this.config.logFolder}`);
      
      // Log loaded scenarios summary
      const fileCount = Object.keys(this.scenarioFiles).length;
      const uniqueFiles = [...new Set(Object.values(this.scenarioFiles))];
      console.log(`📋 Loaded ${fileCount} endpoint(s) from ${uniqueFiles.length} file(s): ${uniqueFiles.join(', ')}`);
      
      // Log CORS configuration
      if (this.config.cors.enabled) {
        console.log(`🌐 CORS: Enabled`);
        console.log(`   Origins: ${Array.isArray(this.config.cors.origin) ? this.config.cors.origin.join(', ') : this.config.cors.origin}`);
        console.log(`   Methods: ${this.config.cors.methods.join(', ')}`);
        console.log(`   Credentials: ${this.config.cors.credentials ? 'Allowed' : 'Not allowed'}`);
      } else {
        console.log(`🌐 CORS: Disabled`);
      }
      
      // Log HTTP proxy configuration if enabled
      if (this.config.httpProxy.enabled) {
        const proxyInfo = `${this.config.httpProxy.protocol}://${this.config.httpProxy.host}:${this.config.httpProxy.port}`;
        const authInfo = this.config.httpProxy.username ? ' (with authentication)' : ' (no authentication)';
        console.log(`🔗 HTTP Proxy: ${proxyInfo}${authInfo}`);
      } else {
        console.log(`🔗 HTTP Proxy: Disabled`);
      }
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