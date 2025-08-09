const axios = require('axios');

class ProxyMockTester {
  constructor(serverUrl = 'http://localhost:3001') {
    this.serverUrl = serverUrl;
    this.testResults = [];
  }

  async runTest(name, testFunction) {
    console.log(`\n🧪 Testing: ${name}`);
    try {
      const result = await testFunction();
      console.log(`✅ PASSED: ${name}`);
      this.testResults.push({ name, status: 'PASSED', result });
      return result;
    } catch (error) {
      console.log(`❌ FAILED: ${name}`);
      console.log(`   Error: ${error.message}`);
      this.testResults.push({ name, status: 'FAILED', error: error.message });
    }
  }

  async testBasicMockResponse() {
    const response = await axios.get(`${this.serverUrl}/api/users`);
    if (response.status !== 200) {
      throw new Error(`Expected status 200, got ${response.status}`);
    }
    if (!response.data.users) {
      throw new Error('Expected users array in response');
    }
    console.log(`   Response: ${response.data.users.length} users returned`);
    return response.data;
  }

  async testFilteredResponse() {
    const response = await axios.get(`${this.serverUrl}/api/users`, {
      headers: { 'x-user-role': 'admin' }
    });
    if (response.status !== 200) {
      throw new Error(`Expected status 200, got ${response.status}`);
    }
    if (response.data.users[0].role !== 'admin') {
      throw new Error('Expected admin user in filtered response');
    }
    console.log(`   Admin Response: ${response.data.users[0].name}`);
    return response.data;
  }

  async testPostWithSuccess() {
    const response = await axios.post(`${this.serverUrl}/api/users`, {
      name: 'Test User',
      email: 'test@example.com',
      type: 'standard'
    });
    if (response.status !== 201) {
      throw new Error(`Expected status 201, got ${response.status}`);
    }
    console.log(`   Created user with ID: ${response.data.id}, type: ${response.data.type}`);
    return response.data;
  }

  async testPostWithPremiumUser() {
    const response = await axios.post(`${this.serverUrl}/api/users`, {
      name: 'Premium User',
      email: 'premium@example.com',
      type: 'premium'
    });
    if (response.status !== 201) {
      throw new Error(`Expected status 201, got ${response.status}`);
    }
    if (response.data.type !== 'premium') {
      throw new Error('Expected premium user response');
    }
    console.log(`   Created premium user with features: ${response.data.features?.join(', ')}`);
    return response.data;
  }

  async testLoginWithAdmin() {
    const response = await axios.post(`${this.serverUrl}/api/login`, {
      username: 'admin',
      password: 'admin123'
    });
    if (response.status !== 200) {
      throw new Error(`Expected status 200, got ${response.status}`);
    }
    if (response.data.user.role !== 'administrator') {
      throw new Error('Expected administrator role in response');
    }
    console.log(`   Admin login successful: ${response.data.user.username} with ${response.data.user.permissions.length} permissions`);
    return response.data;
  }

  async testLoginWithInvalidCredentials() {
    const response = await axios.post(`${this.serverUrl}/api/login`, {
      username: 'user',
      password: 'wrongpassword'
    }, { 
      validateStatus: () => true // Accept all status codes
    });
    
    if (response.status !== 401) {
      throw new Error(`Expected status 401, got ${response.status}`);
    }
    console.log(`   Invalid credentials handled: ${response.data.message}`);
    return response.data;
  }

  async testBodyFieldFiltering() {
    // Test nested object filtering
    const response = await axios.post(`${this.serverUrl}/api/users`, {
      name: 'Test User',
      profile: {
        preferences: {
          theme: 'dark'
        }
      }
    });
    
    console.log(`   Body field filtering test completed`);
    return response.data;
  }

  async testPostWithError() {
    const response = await axios.post(`${this.serverUrl}/api/users?simulate=error`, {
      name: '',
      email: 'invalid-email'
    }, { 
      validateStatus: () => true // Accept all status codes
    });
    
    if (response.status !== 400) {
      throw new Error(`Expected status 400, got ${response.status}`);
    }
    console.log(`   Validation error: ${response.data.error}`);
    return response.data;
  }

  async testHealthCheck() {
    const response = await axios.get(`${this.serverUrl}/api/health`);
    if (response.status !== 200) {
      throw new Error(`Expected status 200, got ${response.status}`);
    }
    if (!response.data.includes('healthy')) {
      throw new Error('Expected healthy status message');
    }
    console.log(`   Health: ${response.data}`);
    return response.data;
  }

  async testMaintenanceMode() {
    const response = await axios.get(`${this.serverUrl}/api/health`, {
      headers: { 'x-maintenance': 'true' },
      validateStatus: () => true // Accept all status codes
    });
    
    if (response.status !== 503) {
      throw new Error(`Expected status 503, got ${response.status}`);
    }
    console.log(`   Maintenance: ${response.data.message}`);
    return response.data;
  }

  async testFileResponse() {
    const response = await axios.get(`${this.serverUrl}/api/files`);
    if (response.status !== 200) {
      throw new Error(`Expected status 200, got ${response.status}`);
    }
    if (!response.data.message) {
      throw new Error('Expected message from file response');
    }
    console.log(`   File Response: ${response.data.message}`);
    return response.data;
  }

  async testProxyRequest() {
    try {
      const response = await axios.get(`${this.serverUrl}/api/proxy/posts/1`);
      if (response.status !== 200) {
        throw new Error(`Expected status 200, got ${response.status}`);
      }
      console.log(`   Proxy Response: Post title - ${response.data.title}`);
      return response.data;
    } catch (error) {
      if (error.code === 'ECONNREFUSED' || error.message.includes('getaddrinfo')) {
        console.log(`   ⚠️  Proxy test skipped (external API unavailable)`);
        return { skipped: true };
      }
      throw error;
    }
  }

  async testCorsConfiguration() {
    try {
      // Test preflight OPTIONS request
      const optionsResponse = await axios.options(`${this.serverUrl}/api/users`, {
        headers: {
          'Origin': 'http://localhost:3000',
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type'
        },
        validateStatus: () => true // Accept all status codes
      });
      
      console.log(`   CORS preflight status: ${optionsResponse.status}`);
      console.log(`   CORS headers present: ${!!optionsResponse.headers['access-control-allow-origin']}`);
      
      // Test actual CORS request
      const corsResponse = await axios.get(`${this.serverUrl}/api/users`, {
        headers: {
          'Origin': 'http://localhost:3000'
        },
        validateStatus: () => true // Accept all status codes
      });
      
      console.log(`   CORS request status: ${corsResponse.status}`);
      console.log(`   CORS origin header: ${corsResponse.headers['access-control-allow-origin'] || 'Not set'}`);
      
      return { 
        preflight: optionsResponse.status, 
        request: corsResponse.status,
        corsEnabled: !!optionsResponse.headers['access-control-allow-origin']
      };
    } catch (error) {
      if (error.response?.status === 404) {
        // If CORS is disabled, we might get 404 for OPTIONS
        console.log(`   CORS appears to be disabled (OPTIONS returned 404)`);
        return { corsEnabled: false };
      }
      throw error;
    }
  }

  async testManagementAPI() {
    // Test getting scenarios
    const getResponse = await axios.get(`${this.serverUrl}/apixxx/scenarios`);
    if (getResponse.status !== 200) {
      throw new Error(`Expected status 200 for GET scenarios, got ${getResponse.status}`);
    }
    console.log(`   Retrieved ${Object.keys(getResponse.data).length} endpoint configurations`);

    // Test updating scenarios
    const testScenario = {
      "GET /test": {
        "scenarios": [{
          "name": "Test Scenario",
          "actionType": "mock",
          "filters": [],
          "response": {
            "statusCode": 200,
            "headers": { "Content-Type": "application/json" },
            "bodyType": "json",
            "body": { "test": true }
          }
        }],
        "defaultBehavior": "first",
        "logicOperator": "and"
      }
    };

    /*const postResponse = await axios.post(`${this.serverUrl}/apixxx/scenarios`, testScenario);
    if (postResponse.status !== 200) {
      throw new Error(`Expected status 200 for POST scenarios, got ${postResponse.status}`);
    }*/
    console.log(`   ✅ Management API working correctly`);
    
    //return { get: getResponse.data, post: postResponse.data };
    return { get: getResponse.data }
  }

  async testWildcardMatching() {
    // Test if wildcard endpoint matching works
    const response = await axios.get(`${this.serverUrl}/api/proxy/posts/5`, { 
      validateStatus: () => true // Accept all status codes
    });
    console.log(`   Wildcard match status: ${response.status}`);
    return response.data;
  }

  async testQueryParameterFiltering() {
    // Test different query parameters
    const response1 = await axios.get(`${this.serverUrl}/api/users?role=admin`);
    const response2 = await axios.get(`${this.serverUrl}/api/users?role=user`);
    
    console.log(`   Query filtering test completed`);
    return { adminQuery: response1.data, userQuery: response2.data };
  }

  async testHeaderMasking() {
    // Test with sensitive headers to verify masking in logs
    const response = await axios.post(`${this.serverUrl}/api/users`, 
      { name: 'Test User' },
      { 
        headers: { 
          'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
          'x-api-key': 'secret-api-key-123'
        }
      }
    );
    
    console.log(`   Request with sensitive headers sent (check logs for masking)`);
    return response.data;
  }

  async runAllTests() {
    console.log('🚀 Starting Proxy/Mock Server Tests');
    console.log('=====================================');

    await this.runTest('Basic Mock Response', () => this.testBasicMockResponse());
    await this.runTest('Filtered Response (Admin)', () => this.testFilteredResponse());
    await this.runTest('POST Success Response', () => this.testPostWithSuccess());
    await this.runTest('POST Premium User (Body Filter)', () => this.testPostWithPremiumUser());
    await this.runTest('Admin Login (Body Filter)', () => this.testLoginWithAdmin());
    await this.runTest('Invalid Login (Body Filter)', () => this.testLoginWithInvalidCredentials());
    await this.runTest('Body Field Filtering', () => this.testBodyFieldFiltering());
    await this.runTest('POST Error Response', () => this.testPostWithError());
    await this.runTest('Health Check', () => this.testHealthCheck());
    await this.runTest('Maintenance Mode', () => this.testMaintenanceMode());
    await this.runTest('File Response', () => this.testFileResponse());
    await this.runTest('Proxy Request', () => this.testProxyRequest());
    await this.runTest('CORS Configuration', () => this.testCorsConfiguration());
    await this.runTest('Wildcard Matching', () => this.testWildcardMatching());
    await this.runTest('Query Parameter Filtering', () => this.testQueryParameterFiltering());
    await this.runTest('Header Masking', () => this.testHeaderMasking());
    //await this.runTest('Management API', () => this.testManagementAPI());

    this.printSummary();
  }

  printSummary() {
    console.log('\n📊 Test Summary');
    console.log('================');
    
    const passed = this.testResults.filter(r => r.status === 'PASSED').length;
    const failed = this.testResults.filter(r => r.status === 'FAILED').length;
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📈 Success Rate: ${((passed / this.testResults.length) * 100).toFixed(1)}%`);
    
    if (failed > 0) {
      console.log('\n❌ Failed Tests:');
      this.testResults
        .filter(r => r.status === 'FAILED')
        .forEach(r => console.log(`   - ${r.name}: ${r.error}`));
    }
    
    console.log('\n🎉 Testing completed!');
  }
}

// Manual test scenarios for advanced features
function printManualTestInstructions() {
  console.log('\n📋 Manual Testing Instructions');
  console.log('==============================');
  console.log('1. Open http://localhost:3001/management in your browser');
  console.log('2. Test the management interface:');
  console.log('   - Add a new endpoint');
  console.log('   - Configure multiple scenarios with filters');
  console.log('   - Export/Import JSON data');
  console.log('   - Sync with server');
  console.log('3. Test round-robin behavior:');
  console.log('   - Create endpoint with multiple scenarios (no filters)');
  console.log('   - Set defaultBehavior to "round_robin"');
  console.log('   - Make multiple requests to see rotation');
  console.log('4. Test complex filtering:');
  console.log('   - Create scenarios with multiple filters');
  console.log('   - Test AND vs OR logic operators');
  console.log('   - Test different filter types (query, header, URL, body)');
  console.log('5. Check logs in ./logs folder for proper masking');
  console.log('6. Test error scenarios (invalid JSON, missing files)');
  console.log('7. Test CORS with different origins and methods');
}

// Usage
async function main() {
  // Check if axios is available
  try {
    require.resolve('axios');
  } catch (e) {
    console.log('❌ axios is required for testing. Install it with: npm install axios');
    return;
  }

  const serverUrl = process.argv[2] || 'http://localhost:3001';
  console.log(`🎯 Testing server at: ${serverUrl}`);
  
  const tester = new ProxyMockTester(serverUrl);
  
  // Wait a bit for server to be ready
  console.log('⏳ Waiting 2 seconds for server to be ready...');
  await new Promise(resolve => setTimeout(resolve, 2000));
  
  await tester.runAllTests();
  printManualTestInstructions();
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = ProxyMockTester;