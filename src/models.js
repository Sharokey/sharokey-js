/**
 * Data models for Sharokey API responses
 * @fileoverview Contains all data models used throughout the library
 */

/**
 * Represents a secret with all its metadata
 * @class
 */
class Secret {
  /**
   * @param {Object} data - Raw secret data from API
   */
  constructor(data) {
    /** @type {string} Secret's unique identifier */
    this.slug = data.slug || '';
    
    /** @type {string} Human-readable description */
    this.description = data.description || '';
    
    /** @type {string} Message for the recipient */
    this.message = data.message || '';
    
    /** @type {string} Email of the secret creator */
    this.creator = data.creator || '';
    
    /** @type {number} Maximum number of views allowed */
    this.maximumViews = data.maximum_views || 0;
    
    /** @type {number} Current number of views */
    this.currentViews = data.current_views || 0;
    
    /** @type {Date} When the secret expires */
    this.expiration = data.expiration ? new Date(data.expiration) : null;
    
    /** @type {boolean} Whether the secret has a password protection */
    this.hasPassword = data.has_password || false;
    
    /** @type {boolean} Whether the secret has file attachments */
    this.hasAttachments = data.has_attachments || false;
    
    /** @type {number} Number of attachments */
    this.attachmentsCount = data.attachments_count || 0;
    
    /** @type {Array} List of attachment details (when available) */
    this.attachments = data.attachments || [];
    
    /** @type {boolean} Whether the secret has expired */
    this.isExpired = data.is_expired || false;
    
    /** @type {string} Current status (active, expired) */
    this.status = data.status || 'unknown';
    
    /** @type {string} Public access URL (without decryption key) */
    this.accessUrl = data.access_url || '';
    
    /** @type {string} Complete sharing URL (with decryption key) */
    this.shareUrl = data.share_url || '';
    
    /** @type {Date} When the secret was created */
    this.createdAt = data.created_at ? new Date(data.created_at) : null;
    
    /** @type {Date} When the secret was last updated */
    this.updatedAt = data.updated_at ? new Date(data.updated_at) : null;
    
    /** @type {boolean} Whether CAPTCHA verification is required */
    this.captcha = data.captcha || false;
    
    /** @type {string|null} OTP type (email, phone) */
    this.otpType = data.otp_type || null;
    
    /** @type {string|null} IP whitelist restrictions */
    this.ipWhitelist = data.ip_whitelist || null;
    
    /** @type {string|null} Geolocation restrictions */
    this.geolocation = data.geolocation || null;
  }

  /**
   * Check if the secret is still active (not expired and has views left)
   * @returns {boolean}
   */
  isActive() {
    return this.status === 'active' && 
           !this.isExpired && 
           this.currentViews < this.maximumViews &&
           (this.expiration === null || this.expiration > new Date());
  }

  /**
   * Get remaining views count
   * @returns {number}
   */
  getRemainingViews() {
    return Math.max(0, this.maximumViews - this.currentViews);
  }

  /**
   * Get time remaining before expiration
   * @returns {number|null} Milliseconds remaining, or null if no expiration
   */
  getTimeRemaining() {
    if (!this.expiration) return null;
    return Math.max(0, this.expiration.getTime() - Date.now());
  }

  /**
   * Convert to plain object
   * @returns {Object}
   */
  toObject() {
    return {
      slug: this.slug,
      description: this.description,
      message: this.message,
      creator: this.creator,
      maximum_views: this.maximumViews,
      current_views: this.currentViews,
      expiration: this.expiration ? this.expiration.toISOString() : null,
      has_password: this.hasPassword,
      has_attachments: this.hasAttachments,
      attachments_count: this.attachmentsCount,
      attachments: this.attachments,
      is_expired: this.isExpired,
      status: this.status,
      access_url: this.accessUrl,
      share_url: this.shareUrl,
      created_at: this.createdAt ? this.createdAt.toISOString() : null,
      updated_at: this.updatedAt ? this.updatedAt.toISOString() : null,
      captcha: this.captcha,
      otp_type: this.otpType,
      ip_whitelist: this.ipWhitelist,
      geolocation: this.geolocation
    };
  }
}

/**
 * Statistics about secrets usage
 * @class
 */
class Statistics {
  /**
   * @param {Object} data - Raw statistics data from API
   */
  constructor(data) {
    /** @type {number} Total number of secrets ever created */
    this.totalSecrets = data.total_secrets || 0;
    
    /** @type {number} Number of currently active secrets */
    this.activeSecrets = data.active_secrets || 0;
    
    /** @type {number} Number of expired secrets */
    this.expiredSecrets = data.expired_secrets || 0;
    
    /** @type {number} Total views across all secrets */
    this.totalViews = data.total_views || 0;
    
    /** @type {number} Number of secrets with password protection */
    this.secretsWithPassword = data.secrets_with_password || 0;
    
    /** @type {number} Secrets created today */
    this.secretsCreatedToday = data.secrets_created_today || 0;
    
    /** @type {number} Secrets created this week */
    this.secretsCreatedThisWeek = data.secrets_created_this_week || 0;
    
    /** @type {number} Secrets created this month */
    this.secretsCreatedThisMonth = data.secrets_created_this_month || 0;
  }

  /**
   * Get the percentage of password-protected secrets
   * @returns {number} Percentage (0-100)
   */
  getPasswordProtectionRate() {
    if (this.totalSecrets === 0) return 0;
    return Math.round((this.secretsWithPassword / this.totalSecrets) * 100);
  }

  /**
   * Get average views per secret
   * @returns {number}
   */
  getAverageViewsPerSecret() {
    if (this.totalSecrets === 0) return 0;
    return Math.round(this.totalViews / this.totalSecrets * 100) / 100;
  }

  /**
   * Convert to plain object
   * @returns {Object}
   */
  toObject() {
    return {
      total_secrets: this.totalSecrets,
      active_secrets: this.activeSecrets,
      expired_secrets: this.expiredSecrets,
      total_views: this.totalViews,
      secrets_with_password: this.secretsWithPassword,
      secrets_created_today: this.secretsCreatedToday,
      secrets_created_this_week: this.secretsCreatedThisWeek,
      secrets_created_this_month: this.secretsCreatedThisMonth
    };
  }
}

/**
 * API response wrapper
 * @class
 * @template T
 */
class ApiResponse {
  /**
   * @param {Object} response - Raw API response
   */
  constructor(response) {
    /** @type {boolean} Whether the request was successful */
    this.success = response.success || false;
    
    /** @type {string} Response message */
    this.message = response.message || '';
    
    /** @type {T} Response data */
    this.data = response.data || null;
    
    /** @type {Object|null} Pagination metadata */
    this.meta = response.meta || null;
    
    /** @type {number|null} HTTP status code */
    this.status = response.status || null;
    
    /** @type {Object|null} Error details */
    this.error = response.error || null;
  }

  /**
   * Check if the response indicates success
   * @returns {boolean}
   */
  isSuccess() {
    return this.success === true;
  }

  /**
   * Check if the response indicates an error
   * @returns {boolean}
   */
  isError() {
    return this.success === false;
  }

  /**
   * Get error message if available
   * @returns {string}
   */
  getErrorMessage() {
    if (this.error && this.error.message) {
      return this.error.message;
    }
    return this.message || 'Unknown error';
  }
}

/**
 * Configuration object for the client
 * @class
 */
class SharokeyConfig {
  /**
   * @param {Object} options - Configuration options
   */
  constructor(options = {}) {
    /** @type {string|null} API authentication token */
    this.token = options.token || null;
    
    /** @type {string} Base URL for the API */
    this.apiUrl = options.apiUrl || 'https://api.sharokey.com/api/v1';
    
    /** @type {number} Request timeout in milliseconds */
    this.timeout = options.timeout || 30000;
    
    /** @type {number} Number of retry attempts for failed requests */
    this.retries = options.retries || 3;
    
    /** @type {number} Default expiration time in hours */
    this.defaultExpirationHours = options.defaultExpirationHours || 24;
    
    /** @type {number} Default maximum views */
    this.defaultMaximumViews = options.defaultMaximumViews || 1;
    
    /** @type {string} Log level (debug, info, warn, error) */
    this.logLevel = options.logLevel || 'info';
    
    /** @type {boolean} Whether to validate SSL certificates */
    this.validateSsl = options.validateSsl !== false;
    
    /** @type {Object} Additional headers to send with requests */
    this.headers = options.headers || {};
  }

  /**
   * Validate the configuration
   * @returns {Array<string>} Array of validation errors
   */
  validate() {
    const errors = [];
    
    if (!this.token) {
      errors.push('API token is required');
    }
    
    if (!this.apiUrl) {
      errors.push('API URL is required');
    }
    
    if (this.timeout <= 0) {
      errors.push('Timeout must be positive');
    }
    
    if (this.retries < 0) {
      errors.push('Retries must be non-negative');
    }
    
    if (this.defaultExpirationHours <= 0 || this.defaultExpirationHours > 8760) {
      errors.push('Default expiration hours must be between 1 and 8760');
    }
    
    if (this.defaultMaximumViews <= 0 || this.defaultMaximumViews > 1000) {
      errors.push('Default maximum views must be between 1 and 1000');
    }
    
    const validLogLevels = ['debug', 'info', 'warn', 'error'];
    if (!validLogLevels.includes(this.logLevel)) {
      errors.push(`Log level must be one of: ${validLogLevels.join(', ')}`);
    }
    
    return errors;
  }

  /**
   * Create a copy of the configuration
   * @returns {SharokeyConfig}
   */
  clone() {
    return new SharokeyConfig({
      token: this.token,
      apiUrl: this.apiUrl,
      timeout: this.timeout,
      retries: this.retries,
      defaultExpirationHours: this.defaultExpirationHours,
      defaultMaximumViews: this.defaultMaximumViews,
      logLevel: this.logLevel,
      validateSsl: this.validateSsl,
      headers: { ...this.headers }
    });
  }
}

/**
 * Request builder for creating secrets
 * @class
 */
class SecretCreateRequest {
  constructor() {
    this.content = '';
    this.description = '';
    this.message = '';
    this.expirationHours = 24;
    this.maximumViews = 1;
    this.password = null;
    this.captcha = false;
    this.ipWhitelist = null;
    this.geolocation = null;
    this.attachments = [];
    this.otpEmail = null;
    this.otpPhone = null;
  }

  /**
   * Set the secret content
   * @param {string} content - The secret content to encrypt
   * @returns {SecretCreateRequest}
   */
  setContent(content) {
    this.content = content;
    return this;
  }

  /**
   * Set the description
   * @param {string} description - Human-readable description
   * @returns {SecretCreateRequest}
   */
  setDescription(description) {
    this.description = description;
    return this;
  }

  /**
   * Set the message for the recipient
   * @param {string} message - Message for the recipient
   * @returns {SecretCreateRequest}
   */
  setMessage(message) {
    this.message = message;
    return this;
  }

  /**
   * Set expiration time in hours
   * @param {number} hours - Hours until expiration (1-8760)
   * @returns {SecretCreateRequest}
   */
  setExpirationHours(hours) {
    this.expirationHours = hours;
    return this;
  }

  /**
   * Set maximum number of views
   * @param {number} views - Maximum views (1-1000)
   * @returns {SecretCreateRequest}
   */
  setMaximumViews(views) {
    this.maximumViews = views;
    return this;
  }

  /**
   * Set password protection
   * @param {string} password - Password for additional protection
   * @returns {SecretCreateRequest}
   */
  setPassword(password) {
    this.password = password;
    return this;
  }

  /**
   * Add a file attachment
   * @param {string} name - File name
   * @param {Buffer|Uint8Array|string} data - File data
   * @returns {SecretCreateRequest}
   */
  addAttachment(name, data) {
    this.attachments.push({ name, data });
    return this;
  }

  /**
   * Set OTP email for additional security
   * @param {string} email - Email for OTP delivery
   * @returns {SecretCreateRequest}
   */
  setOtpEmail(email) {
    this.otpEmail = email;
    return this;
  }

  /**
   * Set OTP phone for additional security
   * @param {string} phone - Phone number for OTP delivery
   * @returns {SecretCreateRequest}
   */
  setOtpPhone(phone) {
    this.otpPhone = phone;
    return this;
  }

  /**
   * Enable CAPTCHA verification
   * @param {boolean} enabled - Whether to enable CAPTCHA
   * @returns {SecretCreateRequest}
   */
  setCaptcha(enabled) {
    this.captcha = enabled;
    return this;
  }

  /**
   * Set IP whitelist restrictions
   * @param {string} ipWhitelist - Comma-separated IPs/CIDR blocks
   * @returns {SecretCreateRequest}
   */
  setIpWhitelist(ipWhitelist) {
    this.ipWhitelist = ipWhitelist;
    return this;
  }

  /**
   * Set geolocation restrictions
   * @param {string} geolocation - Comma-separated country codes
   * @returns {SecretCreateRequest}
   */
  setGeolocation(geolocation) {
    this.geolocation = geolocation;
    return this;
  }

  /**
   * Validate the request
   * @returns {Array<string>} Array of validation errors
   */
  validate() {
    const errors = [];

    if (!this.content || this.content.trim().length === 0) {
      errors.push('Content is required');
    }

    if (this.expirationHours <= 0 || this.expirationHours > 8760) {
      errors.push('Expiration hours must be between 1 and 8760');
    }

    if (this.maximumViews <= 0 || this.maximumViews > 1000) {
      errors.push('Maximum views must be between 1 and 1000');
    }

    if (this.description && this.description.length > 255) {
      errors.push('Description must be 255 characters or less');
    }

    if (this.password && (this.password.length < 4 || this.password.length > 100)) {
      errors.push('Password must be between 4 and 100 characters');
    }

    if (this.attachments.length > 10) {
      errors.push('Maximum 10 attachments allowed');
    }

    if (this.message && this.message.length > 500) {
      errors.push('Message must be 500 characters or less');
    }

    if (this.ipWhitelist && this.ipWhitelist.length > 255) {
      errors.push('IP whitelist must be 255 characters or less');
    }

    if (this.geolocation && this.geolocation.length > 255) {
      errors.push('Geolocation must be 255 characters or less');
    }

    return errors;
  }

  /**
   * Create a static builder instance
   * @returns {SecretCreateRequest}
   */
  static builder() {
    return new SecretCreateRequest();
  }
}

/**
 * Represents a secret request with all its metadata
 * @class
 */
class SecretRequest {
  /**
   * @param {Object} data - Raw secret request data from API
   */
  constructor(data) {
    /** @type {number} Request's unique identifier */
    this.id = data.id || 0;
    
    /** @type {string} Request's unique token */
    this.token = data.token || '';
    
    /** @type {string} Message for the recipient */
    this.message = data.message || '';
    
    /** @type {string} Human-readable description */
    this.description = data.description || '';
    
    /** @type {number} Secret expiration time in hours */
    this.secretExpirationHours = data.secret_expiration_hours || 0;
    
    /** @type {number} Request expiration time in hours */
    this.requestExpirationHours = data.request_expiration_hours || 0;
    
    /** @type {number} Maximum number of views for the secret */
    this.maximumViews = data.maximum_views || 0;
    
    /** @type {string} Email to send the request to */
    this.emailTo = data.email_to || '';
    
    /** @type {string} Email to automatically reply to */
    this.emailReply = data.email_reply || '';
    
    /** @type {string} Email of the request creator */
    this.creator = data.creator || '';
    
    /** @type {Date} When the secret will expire */
    this.secretExpiration = data.secret_expiration ? new Date(data.secret_expiration) : null;
    
    /** @type {Date} When the request expires */
    this.requestExpiration = data.request_expiration ? new Date(data.request_expiration) : null;
    
    /** @type {string} Request status (active/expired) */
    this.status = data.status || 'active';
    
    /** @type {string} Full URL for the request */
    this.url = data.url || '';
    
    /** @type {Date} When the request was created */
    this.createdAt = data.created_at ? new Date(data.created_at) : null;
    
    /** @type {Date} When the request was last updated */
    this.updatedAt = data.updated_at ? new Date(data.updated_at) : null;
  }

  /**
   * Check if the request is still active
   * @returns {boolean}
   */
  isActive() {
    return this.status === 'active' && 
           this.requestExpiration && 
           this.requestExpiration > new Date();
  }

  /**
   * Check if the request has expired
   * @returns {boolean}
   */
  isExpired() {
    return this.status === 'expired' || 
           (this.requestExpiration && this.requestExpiration <= new Date());
  }

  /**
   * Get the share URL for this request
   * @returns {string}
   */
  getShareUrl() {
    return this.url;
  }
}

/**
 * Builder class for creating secret request parameters
 * @class
 */
class SecretRequestCreateRequest {
  constructor() {
    this.message = '';
    this.description = '';
    this.secretExpirationHours = 24;
    this.requestExpirationHours = 48;
    this.maximumViews = 1;
    this.emailTo = '';
    this.emailReply = '';
  }

  /**
   * Set the content/message for the request
   * @param {string} message - Message for the recipient
   * @returns {SecretRequestCreateRequest}
   */
  setMessage(message) {
    this.message = message;
    return this;
  }

  /**
   * Set the description for internal use
   * @param {string} description - Description for the request
   * @returns {SecretRequestCreateRequest}
   */
  setDescription(description) {
    this.description = description;
    return this;
  }

  /**
   * Set secret expiration time in hours
   * @param {number} hours - Hours until secret expiration (1-1000)
   * @returns {SecretRequestCreateRequest}
   */
  setSecretExpirationHours(hours) {
    this.secretExpirationHours = hours;
    return this;
  }

  /**
   * Set request expiration time in hours
   * @param {number} hours - Hours until request expiration (1-1000)
   * @returns {SecretRequestCreateRequest}
   */
  setRequestExpirationHours(hours) {
    this.requestExpirationHours = hours;
    return this;
  }

  /**
   * Set maximum number of views for the secret
   * @param {number} views - Maximum views (1-10)
   * @returns {SecretRequestCreateRequest}
   */
  setMaximumViews(views) {
    this.maximumViews = views;
    return this;
  }

  /**
   * Set email to send the request to
   * @param {string} email - Recipient email address
   * @returns {SecretRequestCreateRequest}
   */
  setEmailTo(email) {
    this.emailTo = email;
    return this;
  }

  /**
   * Set email for automatic reply
   * @param {string} email - Email for automatic reply
   * @returns {SecretRequestCreateRequest}
   */
  setEmailReply(email) {
    this.emailReply = email;
    return this;
  }

  /**
   * Validate the request
   * @returns {Array<string>} Array of validation errors
   */
  validate() {
    const errors = [];

    if (this.secretExpirationHours <= 0 || this.secretExpirationHours > 1000) {
      errors.push('Secret expiration hours must be between 1 and 1000');
    }

    if (this.requestExpirationHours <= 0 || this.requestExpirationHours > 1000) {
      errors.push('Request expiration hours must be between 1 and 1000');
    }

    if (this.maximumViews <= 0 || this.maximumViews > 10) {
      errors.push('Maximum views must be between 1 and 10');
    }

    if (this.description && this.description.length > 255) {
      errors.push('Description must be 255 characters or less');
    }

    if (this.message && this.message.length > 255) {
      errors.push('Message must be 255 characters or less');
    }

    if (this.emailTo && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.emailTo)) {
      errors.push('Email to must be a valid email address');
    }

    if (this.emailReply && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.emailReply)) {
      errors.push('Email reply must be a valid email address');
    }

    return errors;
  }

  /**
   * Create a static builder instance
   * @returns {SecretRequestCreateRequest}
   */
  static builder() {
    return new SecretRequestCreateRequest();
  }
}

module.exports = {
  Secret,
  Statistics,
  ApiResponse,
  SharokeyConfig,
  SecretCreateRequest,
  SecretRequest,
  SecretRequestCreateRequest
};