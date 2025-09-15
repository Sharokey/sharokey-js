/**
 * Sharokey JavaScript Library
 * @fileoverview Secure secret sharing with Zero Knowledge encryption
 * @version 1.0.0
 */

const SharokeyClient = require('./src/client');
const CryptoService = require('./src/crypto');
const { ApiClient, ApiError } = require('./src/api');
const {
  Secret,
  Statistics,
  SharokeyConfig,
  SecretCreateRequest,
  SecretRequest,
  SecretRequestCreateRequest
} = require('./src/models');

/**
 * Create a new Sharokey client instance
 * @param {Object|SharokeyConfig} options - Configuration options
 * @returns {SharokeyClient} New client instance
 */
function createClient(options = {}) {
  return new SharokeyClient(options);
}

/**
 * Create a secret creation request builder
 * @returns {SecretCreateRequest} New request builder
 */
function createSecretRequest() {
  return SecretCreateRequest.builder();
}

/**
 * Create a secret request creation builder
 * @returns {SecretRequestCreateRequest} New request builder
 */
function createSecretRequestRequest() {
  return SecretRequestCreateRequest.builder();
}

// Password generation removed - not part of secure secret sharing core features

/**
 * Validate a Sharokey configuration
 * @param {Object} config - Configuration to validate
 * @returns {Array<string>} Array of validation errors
 */
function validateConfig(config) {
  const sharokeyConfig = new SharokeyConfig(config);
  return sharokeyConfig.validate();
}

// Export main classes and functions
module.exports = {
  // Main client
  SharokeyClient,
  createClient,
  
  // Models
  Secret,
  Statistics,
  SharokeyConfig,
  SecretCreateRequest,
  SecretRequest,
  SecretRequestCreateRequest,
  
  // Services
  CryptoService,
  ApiClient,
  
  // Errors
  ApiError,
  
  // Utilities
  createSecretRequest,
  createSecretRequestRequest,
  validateConfig,
  
  // Version info
  version: '1.0.0'
};

// Default export for ES6 modules compatibility
module.exports.default = SharokeyClient;