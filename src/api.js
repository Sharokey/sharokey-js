/**
 * API client for communicating with Sharokey backend
 * @fileoverview Handles all HTTP requests to the Sharokey API
 */

const { ApiResponse } = require('./models');

/**
 * HTTP methods enum
 * @readonly
 * @enum {string}
 */
const HTTP_METHODS = {
  GET: 'GET',
  POST: 'POST',
  PUT: 'PUT',
  DELETE: 'DELETE'
};

/**
 * API client class for Sharokey backend communication
 * @class
 */
class ApiClient {
  /**
   * @param {SharokeyConfig} config - Configuration object
   */
  constructor(config) {
    this.config = config;
    this.baseUrl = config.apiUrl.replace(/\/$/, ''); // Remove trailing slash
    
    // Check environment
    this.isNode = typeof window === 'undefined';
    
    if (this.isNode) {
      // Node.js environment
      this.fetch = this.createNodeFetch();
    } else {
      // Browser environment
      this.fetch = window.fetch.bind(window);
    }
  }

  /**
   * Create a fetch function for Node.js environment
   * @returns {Function} Fetch-like function
   */
  createNodeFetch() {
    // In a real implementation, you'd use node-fetch or similar
    // For this example, we'll create a basic implementation
    const https = require('https');
    const http = require('http');
    const url = require('url');

    return (urlString, options = {}) => {
      return new Promise((resolve, reject) => {
        const parsedUrl = url.parse(urlString);
        const client = parsedUrl.protocol === 'https:' ? https : http;
        
        const requestOptions = {
          hostname: parsedUrl.hostname,
          port: parsedUrl.port,
          path: parsedUrl.path,
          method: options.method || 'GET',
          headers: options.headers || {},
          timeout: this.config.timeout
        };

        // Add SSL validation option
        if (parsedUrl.protocol === 'https:' && !this.config.validateSsl) {
          requestOptions.rejectUnauthorized = false;
        }

        const req = client.request(requestOptions, (res) => {
          let data = '';
          
          res.on('data', (chunk) => {
            data += chunk;
          });
          
          res.on('end', () => {
            const response = {
              ok: res.statusCode >= 200 && res.statusCode < 300,
              status: res.statusCode,
              statusText: res.statusMessage,
              headers: res.headers,
              json: () => Promise.resolve(JSON.parse(data)),
              text: () => Promise.resolve(data)
            };
            resolve(response);
          });
        });

        req.on('error', reject);
        req.on('timeout', () => {
          req.destroy();
          reject(new Error('Request timeout'));
        });

        if (options.body) {
          req.write(options.body);
        }
        
        req.end();
      });
    };
  }

  /**
   * Get default headers for API requests
   * @returns {Object} Default headers
   */
  getDefaultHeaders() {
    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'Sharokey-JS/1.0.0',
      ...this.config.headers
    };

    if (this.config.token) {
      headers['Authorization'] = `Bearer ${this.config.token}`;
    }

    return headers;
  }

  /**
   * Make an HTTP request with retry logic
   * @param {string} method - HTTP method
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request body data
   * @param {Object} options - Additional options
   * @returns {Promise<ApiResponse>} API response
   */
  async makeRequest(method, endpoint, data = null, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    let lastError;

    for (let attempt = 0; attempt <= this.config.retries; attempt++) {
      try {
        const requestOptions = {
          method: method,
          headers: { ...this.getDefaultHeaders(), ...options.headers },
          ...options
        };

        if (data && (method === 'POST' || method === 'PUT')) {
          requestOptions.body = JSON.stringify(data);
        }

        this.logRequest(method, url, attempt);

        const response = await this.fetch(url, requestOptions);
        const responseData = await response.json();

        this.logResponse(response.status, responseData);

        // Create ApiResponse object
        const apiResponse = new ApiResponse({
          ...responseData,
          status: response.status
        });

        if (!response.ok) {
          throw new ApiError(
            apiResponse.getErrorMessage(),
            response.status,
            apiResponse
          );
        }

        return apiResponse;

      } catch (error) {
        lastError = error;
        
        if (attempt === this.config.retries) {
          break;
        }

        // Don't retry client errors (4xx)
        if (error.status >= 400 && error.status < 500) {
          break;
        }

        // Wait before retrying (exponential backoff)
        const delay = Math.min(1000 * Math.pow(2, attempt), 10000);
        await this.sleep(delay);
        
        this.log('warn', `Request failed, retrying in ${delay}ms (attempt ${attempt + 1}/${this.config.retries})`);
      }
    }

    throw lastError;
  }

  /**
   * GET request
   * @param {string} endpoint - API endpoint
   * @param {Object} params - Query parameters
   * @param {Object} options - Additional options
   * @returns {Promise<ApiResponse>} API response
   */
  async get(endpoint, params = {}, options = {}) {
    const queryString = new URLSearchParams(params).toString();
    const url = queryString ? `${endpoint}?${queryString}` : endpoint;
    
    return this.makeRequest(HTTP_METHODS.GET, url, null, options);
  }

  /**
   * POST request
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request body data
   * @param {Object} options - Additional options
   * @returns {Promise<ApiResponse>} API response
   */
  async post(endpoint, data, options = {}) {
    return this.makeRequest(HTTP_METHODS.POST, endpoint, data, options);
  }

  /**
   * PUT request
   * @param {string} endpoint - API endpoint
   * @param {Object} data - Request body data
   * @param {Object} options - Additional options
   * @returns {Promise<ApiResponse>} API response
   */
  async put(endpoint, data, options = {}) {
    return this.makeRequest(HTTP_METHODS.PUT, endpoint, data, options);
  }

  /**
   * DELETE request
   * @param {string} endpoint - API endpoint
   * @param {Object} options - Additional options
   * @returns {Promise<ApiResponse>} API response
   */
  async delete(endpoint, options = {}) {
    return this.makeRequest(HTTP_METHODS.DELETE, endpoint, null, options);
  }

  /**
   * Test API connectivity
   * @returns {Promise<boolean>} True if API is reachable
   */
  async testConnectivity() {
    try {
      const response = await this.get('/health');
      return response.isSuccess();
    } catch (error) {
      this.log('error', `Connectivity test failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate authentication token
   * @returns {Promise<Object|null>} User information or null if invalid
   */
  async validateToken() {
    try {
      const response = await this.get('/auth/me');
      return response.isSuccess() ? response.data : null;
    } catch (error) {
      this.log('debug', `Token validation failed: ${error.message}`);
      return null;
    }
  }

  /**
   * Authenticate with email and password
   * @param {string} email - User email
   * @param {string} password - User password
   * @returns {Promise<ApiResponse>} Authentication response
   */
  async login(email, password) {
    return this.post('/auth/login', {
      email: email,
      password: password
    });
  }

  /**
   * Authenticate with Microsoft SSO
   * @param {string} accessToken - Microsoft access token
   * @returns {Promise<ApiResponse>} Authentication response
   */
  async loginWithMicrosoft(accessToken) {
    return this.post('/auth/sso', {
      provider: 'microsoft',
      access_token: accessToken
    });
  }

  /**
   * Logout (invalidate token)
   * @returns {Promise<ApiResponse>} Logout response
   */
  async logout() {
    return this.post('/auth/logout');
  }

  /**
   * Create a new secret
   * @param {Object} secretData - Encrypted secret data
   * @returns {Promise<ApiResponse>} Creation response
   */
  async createSecret(secretData) {
    return this.post('/secrets', secretData);
  }

  /**
   * Get list of secrets with optional filters
   * @param {Object} filters - Filtering options
   * @returns {Promise<ApiResponse>} List response
   */
  async listSecrets(filters = {}) {
    const params = {};
    
    if (filters.limit) params.limit = filters.limit;
    if (filters.page) params.page = filters.page;
    if (filters.status) params.status = filters.status;
    if (filters.creator) params.creator = filters.creator;
    if (filters.search) params.search = filters.search;
    
    return this.get('/secrets', params);
  }

  /**
   * Get details of a specific secret
   * @param {string} slug - Secret identifier
   * @returns {Promise<ApiResponse>} Secret details
   */
  async getSecret(slug) {
    return this.get(`/secrets/${slug}`);
  }

  /**
   * Delete a secret
   * @param {string} slug - Secret identifier
   * @returns {Promise<ApiResponse>} Deletion response
   */
  async deleteSecret(slug) {
    return this.delete(`/secrets/${slug}`);
  }

  /**
   * Get usage statistics
   * @returns {Promise<ApiResponse>} Statistics response
   */
  async getStatistics() {
    return this.get('/secrets-stats');
  }

  // ===== SECRET REQUESTS API =====

  /**
   * Create a new secret request
   * @param {Object} requestData - Request data
   * @returns {Promise<ApiResponse>} Created request response
   */
  async createSecretRequest(requestData) {
    return this.post('/requests', requestData);
  }

  /**
   * List secret requests
   * @param {Object} filters - Filtering options
   * @returns {Promise<ApiResponse>} List of secret requests
   */
  async listSecretRequests(filters = {}) {
    return this.get('/requests', filters);
  }

  /**
   * Get specific secret request
   * @param {number|string} id - Request identifier
   * @returns {Promise<ApiResponse>} Secret request details
   */
  async getSecretRequest(id) {
    return this.get(`/requests/${id}`);
  }

  /**
   * Delete a secret request
   * @param {number|string} id - Request identifier
   * @returns {Promise<ApiResponse>} Deletion response
   */
  async deleteSecretRequest(id) {
    return this.delete(`/requests/${id}`);
  }

  /**
   * Get secret request statistics
   * @returns {Promise<ApiResponse>} Statistics response
   */
  async getSecretRequestStatistics() {
    return this.get('/requests-stats');
  }

  /**
   * Upload file attachment
   * @param {string} filename - File name
   * @param {Buffer|Uint8Array} fileData - File data
   * @param {string} mimeType - MIME type
   * @returns {Promise<ApiResponse>} Upload response
   */
  async uploadAttachment(filename, fileData, mimeType = 'application/octet-stream') {
    const formData = new FormData();
    
    let blob;
    if (this.isNode) {
      // Node.js - would need form-data package
      throw new Error('File upload not implemented for Node.js environment');
    } else {
      // Browser
      blob = new Blob([fileData], { type: mimeType });
      formData.append('file', blob, filename);
    }

    return this.makeRequest(HTTP_METHODS.POST, '/attachments', formData, {
      headers: {
        // Don't set Content-Type, let browser set it with boundary
        'Authorization': `Bearer ${this.config.token}`
      }
    });
  }

  /**
   * Sleep utility for retry delays
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   */
  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Log a message based on configuration
   * @param {string} level - Log level
   * @param {string} message - Message to log
   */
  log(level, message) {
    const levels = ['debug', 'info', 'warn', 'error'];
    const configLevel = levels.indexOf(this.config.logLevel);
    const messageLevel = levels.indexOf(level);
    
    if (messageLevel >= configLevel) {
      if (this.isNode) {
        console.log(`[${level.toUpperCase()}] ${message}`);
      } else {
        console[level === 'debug' ? 'log' : level](`[Sharokey] ${message}`);
      }
    }
  }

  /**
   * Log request details
   * @param {string} method - HTTP method
   * @param {string} url - Request URL
   * @param {number} attempt - Attempt number
   */
  logRequest(method, url, attempt) {
    const attemptStr = attempt > 0 ? ` (attempt ${attempt + 1})` : '';
    this.log('debug', `${method} ${url}${attemptStr}`);
  }

  /**
   * Log response details
   * @param {number} status - HTTP status code
   * @param {Object} data - Response data
   */
  logResponse(status, data) {
    const message = data.message || 'No message';
    this.log('debug', `Response ${status}: ${message}`);
  }
}

/**
 * Custom error class for API errors
 * @class
 * @extends Error
 */
class ApiError extends Error {
  /**
   * @param {string} message - Error message
   * @param {number} status - HTTP status code
   * @param {ApiResponse} response - Full API response
   */
  constructor(message, status, response) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.response = response;
  }
}

module.exports = { ApiClient, ApiError };