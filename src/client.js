/**
 * Main Sharokey client class
 * @fileoverview Primary interface for the Sharokey JavaScript library
 */

const CryptoService = require('./crypto');
const { ApiClient, ApiError } = require('./api');
const { 
  Secret, 
  Statistics, 
  SharokeyConfig, 
  SecretCreateRequest,
  SecretRequest,
  SecretRequestCreateRequest
} = require('./models');

/**
 * Main Sharokey client for secure secret sharing
 * @class
 */
class SharokeyClient {
  /**
   * @param {Object|SharokeyConfig} options - Configuration options
   */
  constructor(options = {}) {
    // Ensure we have a proper config object
    this.config = options instanceof SharokeyConfig 
      ? options 
      : new SharokeyConfig(options);
    
    // Validate configuration
    const errors = this.config.validate();
    if (errors.length > 0) {
      throw new Error(`Configuration errors: ${errors.join(', ')}`);
    }
    
    // Initialize services
    this.crypto = new CryptoService();
    this.api = new ApiClient(this.config);
    
    // Cache for user info
    this._userInfo = null;
  }

  /**
   * Test connectivity to the API
   * @returns {Promise<boolean>} True if connected
   */
  async testConnection() {
    try {
      return await this.api.testConnectivity();
    } catch (error) {
      this.log('error', `Connection test failed: ${error.message}`);
      return false;
    }
  }

  /**
   * Validate the current token and get user information
   * @returns {Promise<Object|null>} User info or null if invalid
   */
  async validateToken() {
    try {
      this._userInfo = await this.api.validateToken();
      return this._userInfo;
    } catch (error) {
      this.log('debug', `Token validation failed: ${error.message}`);
      this._userInfo = null;
      return null;
    }
  }

  /**
   * Get current user information (cached)
   * @returns {Object|null} User information
   */
  getCurrentUser() {
    return this._userInfo;
  }

  /**
   * Create a new secret with encryption
   * @param {string|Object|SecretCreateRequest} contentOrRequest - Secret content or full request
   * @param {Object} options - Additional options (used if first param is string)
   * @returns {Promise<Secret>} Created secret information
   */
  async createSecret(contentOrRequest, options = {}) {
    let request;
    
    // Handle different input formats
    if (typeof contentOrRequest === 'string') {
      // Simple string content
      request = SecretCreateRequest.builder()
        .setContent(contentOrRequest)
        .setExpirationHours(options.expirationHours || this.config.defaultExpirationHours)
        .setMaximumViews(options.maximumViews || this.config.defaultMaximumViews);
      
      if (options.description) request.setDescription(options.description);
      if (options.message) request.setMessage(options.message);
      if (options.password) request.setPassword(options.password);
      if (options.captcha) request.setCaptcha(options.captcha);
      if (options.ipWhitelist) request.setIpWhitelist(options.ipWhitelist);
      if (options.geolocation) request.setGeolocation(options.geolocation);
      if (options.otpEmail) request.setOtpEmail(options.otpEmail);
      if (options.otpPhone) request.setOtpPhone(options.otpPhone);
      if (options.attachments) {
        options.attachments.forEach(att => {
          request.addAttachment(att.name, att.data);
        });
      }
    } else if (contentOrRequest instanceof SecretCreateRequest) {
      // SecretCreateRequest object
      request = contentOrRequest;
    } else {
      // Plain object
      request = SecretCreateRequest.builder()
        .setContent(contentOrRequest.content)
        .setExpirationHours(contentOrRequest.expirationHours || this.config.defaultExpirationHours)
        .setMaximumViews(contentOrRequest.maximumViews || this.config.defaultMaximumViews);
      
      if (contentOrRequest.description) request.setDescription(contentOrRequest.description);
      if (contentOrRequest.message) request.setMessage(contentOrRequest.message);
      if (contentOrRequest.password) request.setPassword(contentOrRequest.password);
      if (contentOrRequest.captcha) request.setCaptcha(contentOrRequest.captcha);
      if (contentOrRequest.ipWhitelist) request.setIpWhitelist(contentOrRequest.ipWhitelist);
      if (contentOrRequest.geolocation) request.setGeolocation(contentOrRequest.geolocation);
      if (contentOrRequest.otpEmail) request.setOtpEmail(contentOrRequest.otpEmail);
      if (contentOrRequest.otpPhone) request.setOtpPhone(contentOrRequest.otpPhone);
      if (contentOrRequest.attachments) {
        contentOrRequest.attachments.forEach(att => {
          request.addAttachment(att.name, att.data);
        });
      }
    }

    // Validate the request
    const validationErrors = request.validate();
    if (validationErrors.length > 0) {
      throw new Error(`Validation errors: ${validationErrors.join(', ')}`);
    }

    try {
      // Generate encryption keys
      const keys = this.crypto.generateKeys();
      const keyString = keys.keyA + keys.keyB;
      
      this.log('debug', 'Encrypting secret content...');
      
      // Encrypt the main content
      const encryptionResult = await this.crypto.encrypt(request.content, keyString);
      
      // Prepare API payload
      const payload = {
        content: encryptionResult.content,
        iv: encryptionResult.iv,
        salt: encryptionResult.salt,
        key: encryptionResult.keyA,
        description: request.description || null,
        message: request.message || null,
        maximum_views: request.maximumViews,
        expiration_hours: request.expirationHours,
        password: request.password || null,
        captcha: request.captcha || false,
        ip_whitelist: request.ipWhitelist || null,
        geolocation: request.geolocation || null,
        otp_email: request.otpEmail || null,
        otp_phone: request.otpPhone || null,
        attachments: []
      };

      // Encrypt attachments if any
      if (request.attachments.length > 0) {
        this.log('debug', `Encrypting ${request.attachments.length} attachments...`);
        
        const salt = this.crypto.base64ToArrayBuffer(encryptionResult.salt);
        const iv = this.crypto.base64ToArrayBuffer(encryptionResult.iv);
        
        for (const attachment of request.attachments) {
          const encryptedFile = await this.crypto.encryptFile(
            attachment.data, 
            keyString, 
            iv, 
            salt
          );
          
          payload.attachments.push({
            name: attachment.name,
            data: encryptedFile
          });
        }
      }

      // Send to API
      this.log('debug', 'Sending encrypted data to API...');
      const response = await this.api.createSecret(payload);
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      // Build complete share URL with keyB
      const secret = new Secret(response.data);
      if (secret.accessUrl) {
        secret.shareUrl = `${secret.accessUrl}#${keys.keyB}`;
      }
      
      this.log('info', `Secret created successfully: ${secret.slug}`);
      return secret;
      
    } catch (error) {
      this.log('error', `Failed to create secret: ${error.message}`);
      throw error;
    }
  }

  /**
   * List secrets with optional filtering
   * @param {Object} filters - Filtering options
   * @returns {Promise<{data: Secret[], meta: Object}>} List of secrets with metadata
   */
  async listSecrets(filters = {}) {
    try {
      const response = await this.api.listSecrets(filters);
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      // Handle paginated response from Laravel API
      const secretsData = Array.isArray(response.data) ? response.data : (response.data.items || []);
      const secrets = secretsData.map(item => new Secret(item));
      
      this.log('debug', `Retrieved ${secrets.length} secrets`);
      
      return {
        data: secrets,
        meta: response.meta || {}
      };
      
    } catch (error) {
      this.log('error', `Failed to list secrets: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get details of a specific secret
   * @param {string} slug - Secret identifier
   * @returns {Promise<Secret>} Secret details
   */
  async getSecret(slug) {
    if (!slug || slug.trim().length === 0) {
      throw new Error('Secret slug is required');
    }

    try {
      const response = await this.api.getSecret(slug.trim());
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      const secret = new Secret(response.data);
      this.log('debug', `Retrieved secret: ${secret.slug}`);
      
      return secret;
      
    } catch (error) {
      this.log('error', `Failed to get secret ${slug}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete a secret
   * @param {string} slug - Secret identifier
   * @returns {Promise<boolean>} True if deleted successfully
   */
  async deleteSecret(slug) {
    if (!slug || slug.trim().length === 0) {
      throw new Error('Secret slug is required');
    }

    try {
      const response = await this.api.deleteSecret(slug.trim());
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      this.log('info', `Secret deleted successfully: ${slug}`);
      return true;
      
    } catch (error) {
      this.log('error', `Failed to delete secret ${slug}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get usage statistics
   * @returns {Promise<Statistics>} Usage statistics
   */
  async getStatistics() {
    try {
      const response = await this.api.getStatistics();
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      const stats = new Statistics(response.data);
      this.log('debug', `Retrieved statistics: ${stats.totalSecrets} total secrets`);
      
      return stats;
      
    } catch (error) {
      this.log('error', `Failed to get statistics: ${error.message}`);
      throw error;
    }
  }


  // Password generation methods removed - focus on secure secret sharing core functionality


  /**
   * Search secrets by description or content
   * @param {string} query - Search query
   * @param {Object} options - Search options
   * @returns {Promise<Array<Secret>>} Matching secrets
   */
  async searchSecrets(query, options = {}) {
    if (!query || query.trim().length === 0) {
      throw new Error('Search query is required');
    }

    const filters = {
      search: query.trim(),
      limit: options.limit || 50,
      status: options.status || 'active'
    };

    const result = await this.listSecrets(filters);
    return result.data;
  }

  /**
   * Get active secrets (not expired, with remaining views)
   * @param {number} limit - Maximum number of results
   * @returns {Promise<Array<Secret>>} Active secrets
   */
  async getActiveSecrets(limit = 50) {
    const result = await this.listSecrets({ 
      status: 'active', 
      limit: limit 
    });
    
    return result.data.filter(secret => secret.isActive());
  }

  // ===== SECRET REQUESTS METHODS =====

  /**
   * Create a new secret request
   * @param {Object|SecretRequestCreateRequest} requestOrOptions - Request options
   * @returns {Promise<SecretRequest>} Created secret request information
   */
  async createSecretRequest(requestOrOptions = {}) {
    let request;
    
    // Handle different input formats
    if (requestOrOptions instanceof SecretRequestCreateRequest) {
      // SecretRequestCreateRequest object
      request = requestOrOptions;
    } else {
      // Plain object
      request = SecretRequestCreateRequest.builder()
        .setSecretExpirationHours(requestOrOptions.secretExpirationHours || 24)
        .setRequestExpirationHours(requestOrOptions.requestExpirationHours || 48)
        .setMaximumViews(requestOrOptions.maximumViews || 1);
      
      if (requestOrOptions.message) request.setMessage(requestOrOptions.message);
      if (requestOrOptions.description) request.setDescription(requestOrOptions.description);
      if (requestOrOptions.emailTo) request.setEmailTo(requestOrOptions.emailTo);
      if (requestOrOptions.emailReply) request.setEmailReply(requestOrOptions.emailReply);
    }

    // Validate the request
    const validationErrors = request.validate();
    if (validationErrors.length > 0) {
      throw new Error(`Validation errors: ${validationErrors.join(', ')}`);
    }

    try {
      // Prepare API payload
      const payload = {
        secret_expiration_hours: request.secretExpirationHours,
        request_expiration_hours: request.requestExpirationHours,
        maximum_views: request.maximumViews,
        message: request.message || null,
        description: request.description || null,
        email_to: request.emailTo || null,
        email_reply: request.emailReply || null
      };

      // Send to API
      this.log('debug', 'Creating secret request...');
      const response = await this.api.createSecretRequest(payload);
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      const secretRequest = new SecretRequest(response.data);
      this.log('info', `Secret request created successfully: ${secretRequest.token}`);
      
      return secretRequest;
      
    } catch (error) {
      this.log('error', `Failed to create secret request: ${error.message}`);
      throw error;
    }
  }

  /**
   * List secret requests with optional filtering
   * @param {Object} filters - Filtering options
   * @returns {Promise<{data: SecretRequest[], meta: Object}>} List of secret requests with metadata
   */
  async listSecretRequests(filters = {}) {
    try {
      const response = await this.api.listSecretRequests(filters);
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      // Handle paginated response
      const requestsData = Array.isArray(response.data) ? response.data : (response.data.requests || []);
      const requests = requestsData.map(item => new SecretRequest(item));
      
      this.log('debug', `Retrieved ${requests.length} secret requests`);
      
      return {
        data: requests,
        meta: response.meta || {}
      };
      
    } catch (error) {
      this.log('error', `Failed to list secret requests: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get details of a specific secret request
   * @param {number|string} id - Request identifier
   * @returns {Promise<SecretRequest>} Secret request details
   */
  async getSecretRequest(id) {
    if (!id) {
      throw new Error('Secret request ID is required');
    }

    try {
      const response = await this.api.getSecretRequest(id);
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      const secretRequest = new SecretRequest(response.data);
      this.log('debug', `Retrieved secret request: ${secretRequest.token}`);
      
      return secretRequest;
      
    } catch (error) {
      this.log('error', `Failed to get secret request ${id}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Delete a secret request
   * @param {number|string} id - Request identifier
   * @returns {Promise<boolean>} True if deleted successfully
   */
  async deleteSecretRequest(id) {
    if (!id) {
      throw new Error('Secret request ID is required');
    }

    try {
      const response = await this.api.deleteSecretRequest(id);
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      this.log('info', `Secret request deleted successfully: ${id}`);
      return true;
      
    } catch (error) {
      this.log('error', `Failed to delete secret request ${id}: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get secret request statistics
   * @returns {Promise<Object>} Secret request statistics
   */
  async getSecretRequestStatistics() {
    try {
      const response = await this.api.getSecretRequestStatistics();
      
      if (!response.isSuccess()) {
        throw new ApiError(response.getErrorMessage(), response.status, response);
      }

      this.log('debug', `Retrieved secret request statistics`);
      return response.data;
      
    } catch (error) {
      this.log('error', `Failed to get secret request statistics: ${error.message}`);
      throw error;
    }
  }

  /**
   * Get active secret requests (not expired)
   * @param {number} limit - Maximum number of results
   * @returns {Promise<Array<SecretRequest>>} Active secret requests
   */
  async getActiveSecretRequests(limit = 50) {
    const result = await this.listSecretRequests({ 
      status: 'active', 
      limit: limit 
    });
    
    return result.data.filter(request => request.isActive());
  }


  /**
   * Update client configuration
   * @param {Object} newConfig - New configuration options
   * @returns {SharokeyClient} This client for chaining
   */
  updateConfig(newConfig) {
    const updatedConfig = new SharokeyConfig({
      ...this.config,
      ...newConfig
    });

    const errors = updatedConfig.validate();
    if (errors.length > 0) {
      throw new Error(`Configuration errors: ${errors.join(', ')}`);
    }

    this.config = updatedConfig;
    this.api = new ApiClient(this.config); // Recreate API client
    
    // Clear cached user info as token might have changed
    if (newConfig.token && newConfig.token !== this.config.token) {
      this._userInfo = null;
    }

    return this;
  }

  /**
   * Log message based on configuration
   * @param {string} level - Log level
   * @param {string} message - Message to log
   * @private
   */
  log(level, message) {
    this.api.log(level, message);
  }

  /**
   * Get client information
   * @returns {Object} Client information
   */
  getInfo() {
    return {
      version: '1.0.0',
      apiUrl: this.config.apiUrl,
      hasToken: !!this.config.token,
      logLevel: this.config.logLevel,
      user: this._userInfo
    };
  }
}

module.exports = SharokeyClient;