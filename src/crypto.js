/**
 * Cryptographic service for client-side encryption
 * Implements the same Zero Knowledge encryption as the CLI and Outlook add-in
 * @fileoverview AES-GCM-256 encryption with PBKDF2 key derivation
 */

/**
 * Encryption result containing all necessary data for decryption
 * @typedef {Object} EncryptionResult
 * @property {string} content - Base64 encoded encrypted content
 * @property {string} iv - Base64 encoded initialization vector
 * @property {string} salt - Base64 encoded salt
 * @property {string} keyA - First part of the key (sent to server)
 * @property {string} keyB - Second part of the key (kept for URL)
 */

/**
 * Cryptographic service class
 * @class
 */
class CryptoService {
  constructor() {
    /**
     * Alphanumeric character set for key generation
     * @type {string}
     */
    this.CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    
    /**
     * PBKDF2 iteration count
     * @type {number}
     */
    this.PBKDF2_ITERATIONS = 10000;
    
    /**
     * AES key length in bits
     * @type {number}
     */
    this.AES_KEY_LENGTH = 256;
    
    /**
     * Initialization Vector length in bytes
     * @type {number}
     */
    this.IV_LENGTH = 12;
    
    /**
     * Salt length in bytes
     * @type {number}
     */
    this.SALT_LENGTH = 16;
    
    /**
     * Key A length (sent to server)
     * @type {number}
     */
    this.KEY_A_LENGTH = 8;
    
    /**
     * Key B length (kept for URL)
     * @type {number}
     */
    this.KEY_B_LENGTH = 24;

    // Check if we're in a browser environment
    this.isNode = typeof window === 'undefined';
    
    if (this.isNode) {
      // Node.js environment
      this.crypto = require('crypto');
    } else {
      // Browser environment - use Web Crypto API
      this.crypto = window.crypto || window.msCrypto;
      if (!this.crypto) {
        throw new Error('Web Crypto API not supported in this browser');
      }
    }
  }

  /**
   * Generate a random alphanumeric string
   * @param {number} length - Desired length of the string
   * @returns {string} Random alphanumeric string
   */
  generateAlphanumericKey(length) {
    const array = new Uint8Array(length);
    
    if (this.isNode) {
      // Node.js
      for (let i = 0; i < length; i++) {
        array[i] = this.crypto.randomInt(0, this.CHARSET.length);
      }
    } else {
      // Browser
      this.crypto.getRandomValues(array);
      for (let i = 0; i < length; i++) {
        array[i] = array[i] % this.CHARSET.length;
      }
    }
    
    return Array.from(array, byte => this.CHARSET[byte]).join('');
  }

  /**
   * Generate random bytes
   * @param {number} length - Number of bytes to generate
   * @returns {Uint8Array} Random bytes
   */
  generateRandomBytes(length) {
    const array = new Uint8Array(length);
    
    if (this.isNode) {
      // Node.js
      const buffer = this.crypto.randomBytes(length);
      array.set(buffer);
    } else {
      // Browser
      this.crypto.getRandomValues(array);
    }
    
    return array;
  }

  /**
   * Generate encryption keys (keyA + keyB)
   * @returns {Object} Object with keyA and keyB
   */
  generateKeys() {
    return {
      keyA: this.generateAlphanumericKey(this.KEY_A_LENGTH),
      keyB: this.generateAlphanumericKey(this.KEY_B_LENGTH)
    };
  }

  /**
   * Derive AES key from password using PBKDF2
   * @param {string} password - Password to derive key from
   * @param {Uint8Array} salt - Salt for key derivation
   * @returns {Promise<CryptoKey|Buffer>} Derived AES key
   */
  async deriveKey(password, salt) {
    if (this.isNode) {
      // Node.js implementation
      return new Promise((resolve, reject) => {
        this.crypto.pbkdf2(password, salt, this.PBKDF2_ITERATIONS, this.AES_KEY_LENGTH / 8, 'sha256', (err, key) => {
          if (err) reject(err);
          else resolve(key);
        });
      });
    } else {
      // Browser implementation using Web Crypto API
      const encoder = new TextEncoder();
      const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
      );

      return await window.crypto.subtle.deriveKey(
        {
          name: 'PBKDF2',
          salt: salt,
          iterations: this.PBKDF2_ITERATIONS,
          hash: 'SHA-256'
        },
        keyMaterial,
        {
          name: 'AES-GCM',
          length: this.AES_KEY_LENGTH
        },
        false,
        ['encrypt', 'decrypt']
      );
    }
  }

  /**
   * Encrypt content using AES-GCM
   * @param {string} content - Content to encrypt
   * @param {string} keyString - Complete key (keyA + keyB)
   * @returns {Promise<EncryptionResult>} Encryption result
   */
  async encrypt(content, keyString) {
    try {
      // Generate salt and IV
      const salt = this.generateRandomBytes(this.SALT_LENGTH);
      const iv = this.generateRandomBytes(this.IV_LENGTH);
      
      // Derive AES key from keyString
      const aesKey = await this.deriveKey(keyString, salt);
      
      // Encode content
      const encoder = new TextEncoder();
      const data = encoder.encode(content);
      
      let encryptedData;
      
      if (this.isNode) {
        // Node.js implementation - FIXED
        const cipher = this.crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        
        const encrypted = cipher.update(data);
        const final = cipher.final();
        
        const authTag = cipher.getAuthTag();
        encryptedData = Buffer.concat([encrypted, final, authTag]);
      } else {
        // Browser implementation
        encryptedData = await window.crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: iv
          },
          aesKey,
          data
        );
      }
      
      // Split the key into keyA (server) and keyB (URL)
      const keyA = keyString.substring(0, this.KEY_A_LENGTH);
      const keyB = keyString.substring(this.KEY_A_LENGTH);
      
      // Encode results in base64
      const base64Content = this.arrayBufferToBase64(encryptedData);
      const base64Iv = this.arrayBufferToBase64(iv);
      const base64Salt = this.arrayBufferToBase64(salt);
      
      return {
        content: base64Content,
        iv: base64Iv,
        salt: base64Salt,
        keyA: keyA,
        keyB: keyB
      };
      
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Encrypt a file
   * @param {Buffer|Uint8Array|ArrayBuffer} fileData - File data to encrypt
   * @param {string} keyString - Complete key (keyA + keyB)
   * @param {Uint8Array} iv - Initialization vector (reuse from content encryption)
   * @param {Uint8Array} salt - Salt (reuse from content encryption)
   * @returns {Promise<string>} Base64 encoded encrypted file
   */
  async encryptFile(fileData, keyString, iv, salt) {
    try {
      // Derive AES key
      const aesKey = await this.deriveKey(keyString, salt);
      
      // Ensure fileData is in the right format
      let data;
      if (fileData instanceof ArrayBuffer) {
        data = new Uint8Array(fileData);
      } else if (fileData instanceof Buffer) {
        data = new Uint8Array(fileData);
      } else {
        data = fileData;
      }
      
      let encryptedData;
      
      if (this.isNode) {
        // Node.js implementation
        const cipher = this.crypto.createCipheriv('aes-256-gcm', aesKey, iv);
        
        const encrypted = cipher.update(data);
        const final = cipher.final();
        
        const authTag = cipher.getAuthTag();
        encryptedData = Buffer.concat([encrypted, final, authTag]);
      } else {
        // Browser implementation
        encryptedData = await window.crypto.subtle.encrypt(
          {
            name: 'AES-GCM',
            iv: iv
          },
          aesKey,
          data
        );
      }
      
      return this.arrayBufferToBase64(encryptedData);
      
    } catch (error) {
      throw new Error(`File encryption failed: ${error.message}`);
    }
  }

  /**
   * Convert ArrayBuffer to Base64 string
   * @param {ArrayBuffer|Buffer|Uint8Array} buffer - Buffer to convert
   * @returns {string} Base64 encoded string
   */
  arrayBufferToBase64(buffer) {
    if (this.isNode) {
      // Node.js
      if (buffer instanceof ArrayBuffer) {
        return Buffer.from(buffer).toString('base64');
      }
      return Buffer.from(buffer).toString('base64');
    } else {
      // Browser
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return window.btoa(binary);
    }
  }

  /**
   * Convert Base64 string to Uint8Array
   * @param {string} base64 - Base64 encoded string
   * @returns {Uint8Array} Decoded bytes
   */
  base64ToArrayBuffer(base64) {
    if (this.isNode) {
      // Node.js
      const buffer = Buffer.from(base64, 'base64');
      return new Uint8Array(buffer);
    } else {
      // Browser
      const binary = window.atob(base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      return bytes;
    }
  }

  /**
   * Generate a random password
   * @param {number} length - Password length (default: 16)
   * @param {boolean} includeSymbols - Include special characters (default: true)
   * @returns {string} Generated password
   */
  generatePassword(length = 16, includeSymbols = true) {
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    let charset = lowercase + uppercase + numbers;
    if (includeSymbols) {
      charset += symbols;
    }
    
    const array = new Uint8Array(length);
    if (this.isNode) {
      for (let i = 0; i < length; i++) {
        array[i] = this.crypto.randomInt(0, charset.length);
      }
    } else {
      this.crypto.getRandomValues(array);
      for (let i = 0; i < length; i++) {
        array[i] = array[i] % charset.length;
      }
    }
    
    return Array.from(array, byte => charset[byte]).join('');
  }

  /**
   * Validate encryption parameters
   * @param {string} content - Content to validate
   * @param {string} keyString - Key to validate
   * @returns {Array<string>} Array of validation errors
   */
  validateEncryptionParams(content, keyString) {
    const errors = [];
    
    if (!content || content.length === 0) {
      errors.push('Content cannot be empty');
    }
    
    if (content.length > 1048576) { // 1MB limit
      errors.push('Content too large (max 1MB)');
    }
    
    if (!keyString || keyString.length !== (this.KEY_A_LENGTH + this.KEY_B_LENGTH)) {
      errors.push(`Key must be exactly ${this.KEY_A_LENGTH + this.KEY_B_LENGTH} characters`);
    }
    
    if (keyString && !/^[A-Za-z0-9]+$/.test(keyString)) {
      errors.push('Key must contain only alphanumeric characters');
    }
    
    return errors;
  }
}

module.exports = CryptoService;