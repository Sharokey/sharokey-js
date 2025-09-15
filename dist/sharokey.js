/**
 * Sharokey JavaScript SDK
 * Zero Knowledge secret sharing library
 * 
 * @version 1.0.0
 * @author Sharokey Team
 * @license MIT
 * 
 * Features:
 * - Zero Knowledge encryption (AES-GCM-256 + PBKDF2)
 * - Works in browsers and Node.js
 * - TypeScript support
 * - Complete API coverage
 * - File attachments support
 * - Secret requests workflow
 */

(function(global, factory) {
    if (typeof exports === 'object' && typeof module !== 'undefined') {
        // CommonJS
        module.exports = factory();
    } else if (typeof define === 'function' && define.amd) {
        // AMD
        define(factory);
    } else {
        // Browser global
        global.Sharokey = factory();
    }
})(typeof self !== 'undefined' ? self : this, function() {
    'use strict';

    // ===== CONFIGURATION =====
    
    let globalConfig = {
        token: null,
        apiUrl: 'https://api.sharokey.com/api/v1',
        timeout: 30000,
        debug: false
    };

    // ===== CRYPTO CONSTANTS =====
    
    const CRYPTO_CONFIG = {
        CHARSET: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
        PBKDF2_ITERATIONS: 10000,
        AES_KEY_LENGTH: 256,
        IV_LENGTH: 12,
        SALT_LENGTH: 16,
        KEY_A_LENGTH: 8,
        KEY_B_LENGTH: 24
    };

    // ===== UTILITIES =====
    
    /**
     * Check if Web Crypto API is available
     */
    function checkCryptoSupport() {
        const crypto = global.crypto || global.webcrypto;
        if (!crypto || !crypto.subtle) {
            throw new Error('Web Crypto API not supported. Please use a modern browser.');
        }
        return crypto;
    }

    /**
     * Generate random alphanumeric string
     */
    function generateAlphanumericKey(length) {
        const crypto = checkCryptoSupport();
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        
        return Array.from(array, byte => 
            CRYPTO_CONFIG.CHARSET[byte % CRYPTO_CONFIG.CHARSET.length]
        ).join('');
    }

    /**
     * Generate random bytes
     */
    function generateRandomBytes(length) {
        const crypto = checkCryptoSupport();
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return array;
    }

    /**
     * Convert ArrayBuffer to Base64
     */
    function arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        const chunkSize = 1024;
        
        for (let i = 0; i < bytes.length; i += chunkSize) {
            const chunk = bytes.slice(i, i + chunkSize);
            binary += String.fromCharCode.apply(null, chunk);
        }
        
        return btoa(binary);
    }

    /**
     * Convert Base64 to ArrayBuffer
     */
    function base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    /**
     * Logging utility
     */
    function log(level, message) {
        if (globalConfig.debug) {
            console[level](`[Sharokey] ${message}`);
        }
    }

    // ===== ENCRYPTION SERVICES =====

    /**
     * Encrypt content with AES-GCM
     */
    async function encryptContent(content, keyString) {
        const crypto = checkCryptoSupport();
        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(content);
        
        // Generate salt and IV
        const salt = generateRandomBytes(CRYPTO_CONFIG.SALT_LENGTH);
        const iv = generateRandomBytes(CRYPTO_CONFIG.IV_LENGTH);
        
        // Import key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(keyString),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Derive AES key
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: CRYPTO_CONFIG.AES_KEY_LENGTH },
            false,
            ['encrypt']
        );

        // Encrypt
        const encryptedBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            messageBytes
        );

        return {
            content: arrayBufferToBase64(encryptedBuffer),
            iv: arrayBufferToBase64(iv),
            salt: arrayBufferToBase64(salt),
            keyA: keyString.substring(0, CRYPTO_CONFIG.KEY_A_LENGTH),
            keyB: keyString.substring(CRYPTO_CONFIG.KEY_A_LENGTH)
        };
    }

    /**
     * Encrypt file attachment
     */
    async function encryptFileAttachment(file, keyString, ivBase64, saltBase64) {
        const crypto = checkCryptoSupport();
        
        const arrayBuffer = await file.arrayBuffer();
        const ivBytes = new Uint8Array(base64ToArrayBuffer(ivBase64));
        const saltBytes = new Uint8Array(base64ToArrayBuffer(saltBase64));
        const encoder = new TextEncoder();

        // Import key material
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(keyString),
            'PBKDF2',
            false,
            ['deriveKey']
        );

        // Derive AES-GCM key
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: CRYPTO_CONFIG.AES_KEY_LENGTH },
            false,
            ['encrypt']
        );

        const encryptedBuffer = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: ivBytes
            },
            key,
            arrayBuffer
        );

        return arrayBufferToBase64(encryptedBuffer);
    }

    // ===== API CLIENT =====

    /**
     * Make HTTP request to Sharokey API
     */
    async function makeRequest(method, endpoint, data = null) {
        if (!globalConfig.token) {
            throw new Error('Token not configured. Use Sharokey.config({token: "your-token"}) first.');
        }

        const url = `${globalConfig.apiUrl}${endpoint}`;
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Authorization': `Bearer ${globalConfig.token}`,
                'User-Agent': 'Sharokey-JS-SDK/1.0.0'
            }
        };

        if (data && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
            options.body = JSON.stringify(data);
        }

        // Add timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), globalConfig.timeout);
        options.signal = controller.signal;

        try {
            log('debug', `${method} ${url}`);
            const response = await fetch(url, options);
            clearTimeout(timeoutId);
            
            const responseData = await response.json();

            if (!response.ok) {
                throw new Error(responseData.message || `HTTP ${response.status}: ${response.statusText}`);
            }

            return responseData;
        } catch (error) {
            clearTimeout(timeoutId);
            if (error.name === 'AbortError') {
                throw new Error(`Request timeout after ${globalConfig.timeout}ms`);
            }
            throw new Error(`API Error: ${error.message}`);
        }
    }

    // ===== VALIDATION UTILITIES =====

    /**
     * Validate create parameters
     */
    function validateCreateParams(content, hours, views) {
        if (!content || typeof content !== 'string' || content.trim().length === 0) {
            throw new Error('Content is required and must be a non-empty string');
        }

        hours = parseInt(hours);
        views = parseInt(views);
        
        if (!hours || hours < 1 || hours > 8760) {
            throw new Error('Hours must be between 1 and 8760');
        }
        if (!views || views < 1 || views > 100) {
            throw new Error('Views must be between 1 and 100');
        }

        return { content: content.trim(), hours, views };
    }

    /**
     * Validate security parameters
     */
    function validateSecurityParams(ipWhitelist, geolocation) {
        if (ipWhitelist && ipWhitelist.length > 255) {
            throw new Error('IP whitelist must be 255 characters or less');
        }

        if (geolocation && geolocation.length > 255) {
            throw new Error('Geolocation must be 255 characters or less');
        }

        // Validate IP format
        if (ipWhitelist) {
            const ips = ipWhitelist.split(',').map(ip => ip.trim());
            for (const ip of ips) {
                const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
                if (!ipPattern.test(ip)) {
                    throw new Error(`Invalid IP format: ${ip}. Use format: 192.168.1.1`);
                }
                
                const octets = ip.split('.').map(Number);
                if (octets.some(octet => octet < 0 || octet > 255)) {
                    throw new Error(`Invalid IP range: ${ip}. Each octet must be 0-255`);
                }
            }
        }

        // Validate country codes
        if (geolocation) {
            const countryPattern = /^[A-Z]{2}$/;
            const countries = geolocation.split(',').map(c => c.trim().toUpperCase());
            for (const country of countries) {
                if (!countryPattern.test(country)) {
                    throw new Error(`Invalid country code: ${country}. Use ISO 2-letter codes like FR,US,CA`);
                }
            }
        }
    }

    /**
     * Validate attachments
     */
    function validateAttachments(attachments) {
        const MAX_FILES = 10;
        const MAX_TOTAL_SIZE = 10 * 1024 * 1024; // 10MB

        if (!Array.isArray(attachments)) {
            throw new Error('Attachments must be an array of File objects');
        }

        if (attachments.length > MAX_FILES) {
            throw new Error(`Too many attachments. Maximum ${MAX_FILES} files allowed, got ${attachments.length}`);
        }

        let totalSize = 0;
        for (const file of attachments) {
            if (!(file instanceof File)) {
                throw new Error('Each attachment must be a File object');
            }

            totalSize += file.size;
            if (totalSize > MAX_TOTAL_SIZE) {
                throw new Error(`Total attachments size too large: ${Math.round(totalSize / (1024 * 1024))}MB. Maximum 10MB allowed`);
            }
        }

        return true;
    }

    // ===== SECRET REQUEST VALIDATION =====

    /**
     * Validate secret request parameters
     */
    function validateSecretRequestParams(options) {
        if (!options.secretExpirationHours) {
            throw new Error('secretExpirationHours is required (1-1000 hours)');
        }
        if (!options.requestExpirationHours) {
            throw new Error('requestExpirationHours is required (1-1000 hours)');
        }
        if (!options.maximumViews) {
            throw new Error('maximumViews is required (1-10 views)');
        }

        const secretHours = parseInt(options.secretExpirationHours);
        const requestHours = parseInt(options.requestExpirationHours);
        const maxViews = parseInt(options.maximumViews);

        if (secretHours < 1 || secretHours > 1000) {
            throw new Error('secretExpirationHours must be between 1 and 1000');
        }
        if (requestHours < 1 || requestHours > 1000) {
            throw new Error('requestExpirationHours must be between 1 and 1000');
        }
        if (maxViews < 1 || maxViews > 10) {
            throw new Error('maximumViews must be between 1 and 10');
        }

        return { secretHours, requestHours, maxViews };
    }

    // ===== MAIN SHAROKEY SDK =====

    const Sharokey = {
        /**
         * Configure the Sharokey SDK
         * @param {Object} options - Configuration options
         * @param {string} options.token - API token (required)
         * @param {string} [options.apiUrl] - API base URL
         * @param {number} [options.timeout] - Request timeout in milliseconds
         * @param {boolean} [options.debug] - Enable debug logging
         * @returns {Object} Sharokey SDK instance
         */
        config(options) {
            if (!options || typeof options !== 'object') {
                throw new Error('Configuration object required');
            }

            if (!options.token) {
                throw new Error('Token is required in configuration');
            }

            Object.assign(globalConfig, options);
            log('info', 'Sharokey SDK configured successfully');
            return this;
        },

        /**
         * Create a new secret
         * @param {string} content - Secret content
         * @param {number} [hours=24] - Hours before expiration
         * @param {number} [views=1] - Maximum number of views
         * @param {Object} [options] - Additional options
         * @returns {Promise<Object>} Created secret with share_url
         */
        async create(content, hours = 24, views = 1, options = {}) {
            const params = validateCreateParams(content, hours, views);
            
            // Validate OTP options
            if (options.otpEmail && options.otpPhone) {
                throw new Error('Cannot use both otpEmail and otpPhone options simultaneously');
            }

            if (options.otpEmail) {
                const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailPattern.test(options.otpEmail)) {
                    throw new Error('Invalid email format for OTP');
                }
            }

            if (options.otpPhone) {
                const phonePattern = /^\+\d{11,15}$/;
                if (!phonePattern.test(options.otpPhone)) {
                    throw new Error('Invalid phone format for OTP. Use format: +33674747474');
                }
            }

            // Validate security parameters
            validateSecurityParams(options.ipWhitelist, options.geolocation);

            // Validate attachments
            if (options.attachments && options.attachments.length > 0) {
                validateAttachments(options.attachments);
            }
            
            // Generate encryption keys
            const keyA = generateAlphanumericKey(CRYPTO_CONFIG.KEY_A_LENGTH);
            const keyB = generateAlphanumericKey(CRYPTO_CONFIG.KEY_B_LENGTH);
            const keyString = keyA + keyB;

            log('debug', 'Encrypting secret content...');
            
            // Encrypt the content
            const encrypted = await encryptContent(params.content, keyString);

            // Prepare API payload
            const payload = {
                content: encrypted.content,
                iv: encrypted.iv,
                salt: encrypted.salt,
                key: encrypted.keyA,
                maximum_views: params.views,
                expiration_hours: params.hours,
                attachments: []
            };

            // Encrypt attachments if provided
            if (options.attachments && options.attachments.length > 0) {
                log('debug', `Encrypting ${options.attachments.length} attachments...`);
                
                for (const file of options.attachments) {
                    try {
                        const encryptedFileData = await encryptFileAttachment(
                            file, 
                            keyString, 
                            encrypted.iv, 
                            encrypted.salt
                        );
                        
                        payload.attachments.push({
                            name: file.name,
                            data: encryptedFileData
                        });
                    } catch (error) {
                        throw new Error(`Failed to encrypt file ${file.name}: ${error.message}`);
                    }
                }
            }

            // Add optional parameters
            if (options.description) payload.description = options.description;
            if (options.message) payload.message = options.message;
            if (options.password) payload.password = options.password;
            if (options.captcha) payload.captcha = options.captcha;
            if (options.ipWhitelist) payload.ip_whitelist = options.ipWhitelist;
            if (options.geolocation) payload.geolocation = options.geolocation;
            if (options.otpEmail) {
                payload.otp_type = 'email';
                payload.otp_receiver = options.otpEmail;
            }
            if (options.otpPhone) {
                payload.otp_type = 'phone';
                payload.otp_receiver = options.otpPhone;
            }

            // Send to API
            log('debug', 'Sending encrypted data to API...');
            const response = await makeRequest('POST', '/secrets', payload);

            // Build complete share URL with keyB
            const secret = response.data;
            if (secret.access_url) {
                secret.share_url = `${secret.access_url}#${keyB}`;
            }

            log('info', `Secret created successfully: ${secret.slug}`);
            return secret;
        },

        /**
         * List secrets with optional filtering
         * @param {Object} [options] - Filtering options
         * @param {number} [options.limit=50] - Maximum number of results
         * @param {string} [options.status] - Filter by status (active|expired)
         * @param {string} [options.creator] - Filter by creator
         * @param {string} [options.search] - Search in descriptions
         * @returns {Promise<Object>} List of secrets
         */
        async list(options = {}) {
            const params = new URLSearchParams();
            
            if (options.limit) params.set('limit', options.limit);
            if (options.status) params.set('status', options.status);
            if (options.creator) params.set('creator', options.creator);
            if (options.search) params.set('search', options.search);

            const queryString = params.toString();
            const endpoint = queryString ? `/secrets?${queryString}` : '/secrets';
            
            const response = await makeRequest('GET', endpoint);
            log('debug', `Retrieved ${response.data?.length || 0} secrets`);
            return response;
        },

        /**
         * Get secret details
         * @param {string} slug - Secret identifier
         * @returns {Promise<Object>} Secret details
         */
        async get(slug) {
            if (!slug || typeof slug !== 'string') {
                throw new Error('Secret slug is required');
            }

            const response = await makeRequest('GET', `/secrets/${slug.trim()}`);
            log('debug', `Retrieved secret: ${slug}`);
            return response;
        },

        /**
         * Delete a secret
         * @param {string} slug - Secret identifier
         * @returns {Promise<Object>} Deletion confirmation
         */
        async delete(slug) {
            if (!slug || typeof slug !== 'string') {
                throw new Error('Secret slug is required');
            }

            const response = await makeRequest('DELETE', `/secrets/${slug.trim()}`);
            log('info', `Secret deleted: ${slug}`);
            return response;
        },

        /**
         * Get usage statistics
         * @returns {Promise<Object>} Usage statistics
         */
        async stats() {
            const response = await makeRequest('GET', '/secrets-stats');
            log('debug', 'Retrieved statistics');
            return response;
        },

        /**
         * Test API connectivity and authentication
         * @returns {Promise<Object>} Test results with detailed diagnostics
         */
        async test() {
            const results = {
                config: false,
                network: false,
                auth: false,
                read: false,
                stats: false,
                total: 5,
                passed: 0,
                success: false,
                details: []
            };

            try {
                // 1. Test configuration
                if (globalConfig.token) {
                    results.config = true;
                    results.passed++;
                    results.details.push('✅ Configuration: Token present');
                } else {
                    results.details.push('❌ Configuration: No token configured');
                }

                // 2. Test network connectivity
                try {
                    await makeRequest('GET', '/health');
                    results.network = true;
                    results.passed++;
                    results.details.push('✅ Network: API server reachable');
                } catch (e) {
                    results.details.push(`❌ Network: ${e.message}`);
                }

                // 3. Test authentication + read permissions
                try {
                    await this.list({ limit: 1 });
                    results.auth = true;
                    results.read = true;
                    results.passed += 2;
                    results.details.push('✅ Authentication: Token valid');
                    results.details.push('✅ Read Access: Secrets list accessible');
                } catch (e) {
                    results.details.push(`❌ Authentication/Read: ${e.message}`);
                }

                // 4. Test statistics access
                try {
                    await this.stats();
                    results.stats = true;
                    results.passed++;
                    results.details.push('✅ Statistics: Stats accessible');
                } catch (e) {
                    results.details.push(`❌ Statistics: ${e.message}`);
                }

                results.success = results.passed === results.total;
                
                log('info', `Connectivity test completed: ${results.passed}/${results.total} checks passed`);
                return results;

            } catch (error) {
                results.error = error.message;
                results.details.push(`❌ General Error: ${error.message}`);
                return results;
            }
        },

        // ===== SECRET REQUESTS METHODS =====

        /**
         * Create a secret request
         * @param {Object} options - Request options
         * @param {number} options.secretExpirationHours - Hours for secret expiration (1-1000)
         * @param {number} options.requestExpirationHours - Hours for request expiration (1-1000)
         * @param {number} options.maximumViews - Maximum views (1-10)
         * @param {string} [options.message] - Message for recipient
         * @param {string} [options.description] - Internal description
         * @param {string} [options.emailTo] - Recipient email
         * @param {string} [options.emailReply] - Reply email
         * @param {string} [options.locale] - Email locale (en|fr)
         * @returns {Promise<Object>} Created secret request
         */
        async createRequest(options = {}) {
            const params = validateSecretRequestParams(options);

            const requestData = {
                secret_expiration_hours: params.secretHours,
                request_expiration_hours: params.requestHours,
                maximum_views: params.maxViews
            };

            if (options.message) requestData.message = options.message;
            if (options.description) requestData.description = options.description;
            if (options.emailTo) requestData.email_to = options.emailTo;
            if (options.emailReply) requestData.email_reply = options.emailReply;
            if (options.locale) requestData.locale = options.locale;

            const response = await makeRequest('POST', '/requests', requestData);
            log('info', `Secret request created: ${response.data?.token || 'unknown'}`);
            return response.data;
        },

        /**
         * List secret requests
         * @param {Object} [options] - Filtering options
         * @param {number} [options.limit=50] - Maximum results
         * @param {string} [options.status] - Filter by status (active|expired)
         * @param {string} [options.creator] - Filter by creator
         * @param {string} [options.search] - Search in descriptions
         * @returns {Promise<Object>} List of secret requests
         */
        async listRequests(options = {}) {
            const params = new URLSearchParams();
            
            if (options.limit) params.append('limit', options.limit);
            if (options.status) params.append('status', options.status);
            if (options.creator) params.append('creator', options.creator);
            if (options.search) params.append('search', options.search);

            const query = params.toString();
            const endpoint = query ? `/requests?${query}` : '/requests';
            
            const response = await makeRequest('GET', endpoint);
            log('debug', `Retrieved ${response.data?.length || 0} secret requests`);
            return response;
        },

        /**
         * Get secret request details
         * @param {string} token - Request token
         * @returns {Promise<Object>} Secret request details
         */
        async getRequest(token) {
            if (!token || typeof token !== 'string') {
                throw new Error('Request token is required');
            }
            
            const response = await makeRequest('GET', `/requests/${token.trim()}`);
            log('debug', `Retrieved secret request: ${token}`);
            return response.data;
        },

        /**
         * Delete a secret request
         * @param {string} token - Request token
         * @returns {Promise<Object>} Deletion confirmation
         */
        async deleteRequest(token) {
            if (!token || typeof token !== 'string') {
                throw new Error('Request token is required');
            }
            
            const response = await makeRequest('DELETE', `/requests/${token.trim()}`);
            log('info', `Secret request deleted: ${token}`);
            return response;
        },

        /**
         * Get secret request statistics
         * @returns {Promise<Object>} Request statistics
         */
        async requestStats() {
            const response = await makeRequest('GET', '/requests-stats');
            log('debug', 'Retrieved request statistics');
            return response;
        },

        // ===== UTILITY METHODS =====

        /**
         * Get current configuration (without sensitive data)
         * @returns {Object} Current configuration
         */
        getConfig() {
            return {
                apiUrl: globalConfig.apiUrl,
                timeout: globalConfig.timeout,
                debug: globalConfig.debug,
                hasToken: !!globalConfig.token
            };
        },

        /**
         * Test simple connectivity (returns boolean)
         * @returns {Promise<boolean>} True if connected
         */
        async testConnection() {
            const results = await this.test();
            return results.success;
        },

        /**
         * Get active secrets only
         * @param {Object} [options] - Filtering options
         * @returns {Promise<Object>} Active secrets only
         */
        async getActiveSecrets(options = {}) {
            return this.list({ ...options, status: 'active' });
        },

        /**
         * Get active secret requests only
         * @param {Object} [options] - Filtering options
         * @returns {Promise<Object>} Active secret requests only
         */
        async getActiveRequests(options = {}) {
            return this.listRequests({ ...options, status: 'active' });
        },

        /**
         * Search secrets by description/content
         * @param {string} query - Search query
         * @param {Object} [options] - Additional options
         * @returns {Promise<Object>} Search results
         */
        async search(query, options = {}) {
            if (!query || query.trim().length === 0) {
                throw new Error('Search query is required');
            }

            return this.list({ ...options, search: query.trim() });
        },

        // ===== SDK INFO =====

        /**
         * SDK version
         */
        version: '1.0.0',

        /**
         * Get SDK information
         * @returns {Object} SDK information
         */
        getInfo() {
            return {
                name: 'Sharokey JavaScript SDK',
                version: this.version,
                config: this.getConfig(),
                features: [
                    'Zero Knowledge Encryption',
                    'File Attachments',
                    'Secret Requests',
                    'Advanced Security Options',
                    'Browser & Node.js Support',
                    'TypeScript Support'
                ],
                crypto: {
                    algorithm: 'AES-GCM-256',
                    keyDerivation: 'PBKDF2',
                    iterations: CRYPTO_CONFIG.PBKDF2_ITERATIONS
                }
            };
        }
    };

    return Sharokey;
});