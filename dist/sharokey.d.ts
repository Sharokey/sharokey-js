/**
 * Sharokey JavaScript SDK TypeScript Definitions
 * @version 1.0.0
 */

declare namespace Sharokey {
  // ===== Configuration Types =====
  
  interface SharokeyConfig {
    /** API authentication token (required) */
    token: string;
    /** API base URL (default: https://api.sharokey.com/api/v1) */
    apiUrl?: string;
    /** Request timeout in milliseconds (default: 30000) */
    timeout?: number;
    /** Enable debug logging (default: false) */
    debug?: boolean;
  }

  interface CurrentConfig {
    apiUrl: string;
    timeout: number;
    debug: boolean;
    hasToken: boolean;
  }

  // ===== Secret Types =====

  interface SecretCreateOptions {
    /** Description for the secret */
    description?: string;
    /** Message for the recipient */
    message?: string;
    /** Password protection */
    password?: string;
    /** Enable CAPTCHA verification */
    captcha?: boolean;
    /** Comma-separated list of allowed IP addresses */
    ipWhitelist?: string;
    /** Comma-separated list of allowed country codes (ISO 2-letter) */
    geolocation?: string;
    /** Email for OTP verification */
    otpEmail?: string;
    /** Phone number for OTP verification (format: +33674747474) */
    otpPhone?: string;
    /** File attachments (max 10 files, 10MB total) */
    attachments?: File[];
  }

  interface Secret {
    /** Unique secret identifier */
    slug: string;
    /** Access URL (without keyB) */
    access_url: string;
    /** Complete share URL (with keyB in fragment) */
    share_url?: string;
    /** Secret description */
    description?: string;
    /** Message for recipient */
    message?: string;
    /** Maximum number of views */
    maximum_views: number;
    /** Remaining views */
    remaining_views: number;
    /** Expiration date */
    expires_at: string;
    /** Creation date */
    created_at: string;
    /** Whether secret is still active */
    is_active: boolean;
    /** Has password protection */
    has_password: boolean;
    /** Has CAPTCHA protection */
    has_captcha: boolean;
    /** Has file attachments */
    has_attachments: boolean;
    /** Number of attachments */
    attachments_count?: number;
    /** Creator information */
    creator?: string;
  }

  interface SecretListOptions {
    /** Maximum number of results (default: 50) */
    limit?: number;
    /** Filter by status */
    status?: 'active' | 'expired';
    /** Filter by creator email */
    creator?: string;
    /** Search in descriptions */
    search?: string;
  }

  interface SecretListResponse {
    data: Secret[];
    meta?: {
      total?: number;
      per_page?: number;
      current_page?: number;
      last_page?: number;
    };
  }

  // ===== Secret Request Types =====

  interface SecretRequestCreateOptions {
    /** Hours before the created secret expires (1-1000) */
    secretExpirationHours: number;
    /** Hours before the request itself expires (1-1000) */
    requestExpirationHours: number;
    /** Maximum views for the created secret (1-10) */
    maximumViews: number;
    /** Message for the recipient */
    message?: string;
    /** Internal description */
    description?: string;
    /** Recipient email address */
    emailTo?: string;
    /** Reply email address */
    emailReply?: string;
    /** Email language (en or fr) */
    locale?: 'en' | 'fr';
  }

  interface SecretRequest {
    /** Request token */
    token: string;
    /** Request URL */
    url?: string;
    /** Message for recipient */
    message?: string;
    /** Internal description */
    description?: string;
    /** Secret expiration hours */
    secret_expiration_hours: number;
    /** Request expiration hours */
    request_expiration_hours: number;
    /** Maximum views */
    maximum_views: number;
    /** Recipient email */
    email_to?: string;
    /** Reply email */
    email_reply?: string;
    /** Request creation date */
    created_at: string;
    /** Request expiration date */
    expires_at: string;
    /** Whether request is still active */
    is_active: boolean;
    /** Creator information */
    creator?: string;
  }

  interface SecretRequestListOptions {
    /** Maximum number of results (default: 50) */
    limit?: number;
    /** Filter by status */
    status?: 'active' | 'expired';
    /** Filter by creator email */
    creator?: string;
    /** Search in descriptions */
    search?: string;
  }

  // ===== Statistics Types =====

  interface Statistics {
    /** Total number of secrets created */
    total_secrets: number;
    /** Number of active secrets */
    active_secrets: number;
    /** Number of expired secrets */
    expired_secrets: number;
    /** Total views */
    total_views: number;
    /** Statistics for current month */
    current_month?: {
      secrets_created: number;
      total_views: number;
    };
  }

  // ===== Test Results =====

  interface TestResults {
    /** Configuration test passed */
    config: boolean;
    /** Network connectivity test passed */
    network: boolean;
    /** Authentication test passed */
    auth: boolean;
    /** Read access test passed */
    read: boolean;
    /** Statistics access test passed */
    stats: boolean;
    /** Total number of tests */
    total: number;
    /** Number of tests passed */
    passed: number;
    /** Overall success */
    success: boolean;
    /** Detailed test results */
    details: string[];
    /** Error message if any */
    error?: string;
  }

  // ===== SDK Info =====

  interface SdkInfo {
    name: string;
    version: string;
    config: CurrentConfig;
    features: string[];
    crypto: {
      algorithm: string;
      keyDerivation: string;
      iterations: number;
    };
  }
}

// ===== Main SDK Interface =====

interface SharokeySDK {
  /**
   * Configure the Sharokey SDK
   * @param options Configuration options
   * @returns SDK instance for chaining
   */
  config(options: Sharokey.SharokeyConfig): SharokeySDK;

  /**
   * Create a new secret
   * @param content Secret content
   * @param hours Hours before expiration (default: 24)
   * @param views Maximum number of views (default: 1)
   * @param options Additional options
   * @returns Promise resolving to created secret
   */
  create(
    content: string,
    hours?: number,
    views?: number,
    options?: Sharokey.SecretCreateOptions
  ): Promise<Sharokey.Secret>;

  /**
   * List secrets with optional filtering
   * @param options Filtering options
   * @returns Promise resolving to list of secrets
   */
  list(options?: Sharokey.SecretListOptions): Promise<Sharokey.SecretListResponse>;

  /**
   * Get details of a specific secret
   * @param slug Secret identifier
   * @returns Promise resolving to secret details
   */
  get(slug: string): Promise<{ data: Sharokey.Secret }>;

  /**
   * Delete a secret
   * @param slug Secret identifier
   * @returns Promise resolving to deletion confirmation
   */
  delete(slug: string): Promise<{ message: string }>;

  /**
   * Get usage statistics
   * @returns Promise resolving to statistics
   */
  stats(): Promise<{ data: Sharokey.Statistics }>;

  /**
   * Test API connectivity and authentication
   * @returns Promise resolving to detailed test results
   */
  test(): Promise<Sharokey.TestResults>;

  /**
   * Test simple connectivity (returns boolean)
   * @returns Promise resolving to connection status
   */
  testConnection(): Promise<boolean>;

  // ===== Secret Request Methods =====

  /**
   * Create a secret request
   * @param options Request creation options
   * @returns Promise resolving to created request
   */
  createRequest(options: Sharokey.SecretRequestCreateOptions): Promise<Sharokey.SecretRequest>;

  /**
   * List secret requests with optional filtering
   * @param options Filtering options
   * @returns Promise resolving to list of requests
   */
  listRequests(options?: Sharokey.SecretRequestListOptions): Promise<{ data: Sharokey.SecretRequest[] }>;

  /**
   * Get details of a specific secret request
   * @param token Request token
   * @returns Promise resolving to request details
   */
  getRequest(token: string): Promise<Sharokey.SecretRequest>;

  /**
   * Delete a secret request
   * @param token Request token
   * @returns Promise resolving to deletion confirmation
   */
  deleteRequest(token: string): Promise<{ message: string }>;

  /**
   * Get secret request statistics
   * @returns Promise resolving to request statistics
   */
  requestStats(): Promise<{ data: any }>;

  // ===== Utility Methods =====

  /**
   * Get current configuration (without sensitive data)
   * @returns Current configuration
   */
  getConfig(): Sharokey.CurrentConfig;

  /**
   * Get active secrets only
   * @param options Filtering options
   * @returns Promise resolving to active secrets
   */
  getActiveSecrets(options?: Sharokey.SecretListOptions): Promise<Sharokey.SecretListResponse>;

  /**
   * Get active secret requests only
   * @param options Filtering options
   * @returns Promise resolving to active requests
   */
  getActiveRequests(options?: Sharokey.SecretRequestListOptions): Promise<{ data: Sharokey.SecretRequest[] }>;

  /**
   * Search secrets by description/content
   * @param query Search query
   * @param options Additional options
   * @returns Promise resolving to search results
   */
  search(query: string, options?: Sharokey.SecretListOptions): Promise<Sharokey.SecretListResponse>;

  /**
   * Get SDK information
   * @returns SDK information and capabilities
   */
  getInfo(): Sharokey.SdkInfo;

  /** SDK version */
  readonly version: string;
}

// ===== Module Declarations =====

declare const Sharokey: SharokeySDK;

// CommonJS export
export = Sharokey;

// ES Module export
export default Sharokey;

// Named exports for ES modules
export const config: SharokeySDK['config'];
export const create: SharokeySDK['create'];
export const list: SharokeySDK['list'];
export const get: SharokeySDK['get'];
export const deleteSecret: SharokeySDK['delete'];
export const stats: SharokeySDK['stats'];
export const test: SharokeySDK['test'];
export const testConnection: SharokeySDK['testConnection'];
export const createRequest: SharokeySDK['createRequest'];
export const listRequests: SharokeySDK['listRequests'];
export const getRequest: SharokeySDK['getRequest'];
export const deleteRequest: SharokeySDK['deleteRequest'];
export const requestStats: SharokeySDK['requestStats'];
export const getConfig: SharokeySDK['getConfig'];
export const getActiveSecrets: SharokeySDK['getActiveSecrets'];
export const getActiveRequests: SharokeySDK['getActiveRequests'];
export const search: SharokeySDK['search'];
export const getInfo: SharokeySDK['getInfo'];
export const version: string;

// Global declaration for browser usage
declare global {
  const Sharokey: SharokeySDK;
}