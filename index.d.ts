/**
 * TypeScript definitions for Sharokey JavaScript Library
 */

export interface SharokeyConfigOptions {
  /** API authentication token */
  token?: string;
  /** Base URL for the API */
  apiUrl?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Number of retry attempts for failed requests */
  retries?: number;
  /** Default expiration time in hours */
  defaultExpirationHours?: number;
  /** Default maximum views */
  defaultMaximumViews?: number;
  /** Log level */
  logLevel?: 'debug' | 'info' | 'warn' | 'error';
  /** Whether to validate SSL certificates */
  validateSsl?: boolean;
  /** Additional headers to send with requests */
  headers?: Record<string, string>;
}

export interface AttachmentData {
  /** File name */
  name: string;
  /** File data */
  data: Buffer | Uint8Array | ArrayBuffer;
}

export interface SecretCreateOptions {
  /** Secret content */
  content: string;
  /** Human-readable description */
  description?: string;
  /** Message for the recipient */
  message?: string;
  /** Hours until expiration */
  expirationHours?: number;
  /** Maximum number of views */
  maximumViews?: number;
  /** Password for additional protection */
  password?: string;
  /** Enable CAPTCHA verification */
  captcha?: boolean;
  /** IP whitelist (comma-separated IPs/CIDR blocks) */
  ipWhitelist?: string;
  /** Geolocation restrictions (comma-separated country codes) */
  geolocation?: string;
  /** File attachments */
  attachments?: AttachmentData[];
  /** Email for OTP delivery */
  otpEmail?: string;
  /** Phone number for OTP delivery */
  otpPhone?: string;
}

export interface SecretRequestCreateOptions {
  /** Message for the recipient */
  message?: string;
  /** Description for internal use */
  description?: string;
  /** Hours until secret expiration */
  secretExpirationHours?: number;
  /** Hours until request expiration */
  requestExpirationHours?: number;
  /** Maximum number of views for the secret */
  maximumViews?: number;
  /** Email to send the request to */
  emailTo?: string;
  /** Email for automatic reply */
  emailReply?: string;
}

export interface SecretRequestListFilters {
  /** Maximum number of results */
  limit?: number;
  /** Page number for pagination */
  page?: number;
  /** Filter by status */
  status?: 'active' | 'expired';
  /** Filter by creator email */
  creator?: string;
  /** Search in description/message */
  search?: string;
}

export interface SecretListFilters {
  /** Maximum number of results */
  limit?: number;
  /** Page number for pagination */
  page?: number;
  /** Filter by status */
  status?: 'active' | 'expired';
  /** Filter by creator email */
  creator?: string;
  /** Search in description/slug */
  search?: string;
}

export interface ListResponse<T> {
  /** Array of results */
  data: T[];
  /** Pagination metadata */
  meta: {
    current_page: number;
    per_page: number;
    total: number;
    last_page: number;
  };
}

export interface CleanupResult {
  /** Array of deleted secret slugs */
  deleted: string[];
  /** Array of errors */
  errors: Array<{ slug: string; error: string }>;
}

export interface BatchSecretResult {
  /** Successfully created secret */
  secret: Secret;
  /** Generated password (if applicable) */
  password?: string;
}

export interface ClientInfo {
  /** Library version */
  version: string;
  /** API URL */
  apiUrl: string;
  /** Whether token is configured */
  hasToken: boolean;
  /** Current log level */
  logLevel: string;
  /** Current user info */
  user: any;
}

/**
 * Secret request model class
 */
export declare class SecretRequest {
  id: number;
  token: string;
  message: string;
  description: string;
  secretExpirationHours: number;
  requestExpirationHours: number;
  maximumViews: number;
  emailTo: string;
  emailReply: string;
  creator: string;
  secretExpiration: Date | null;
  requestExpiration: Date | null;
  status: string;
  url: string;
  createdAt: Date | null;
  updatedAt: Date | null;

  /** Check if the request is still active */
  isActive(): boolean;
  /** Check if the request has expired */
  isExpired(): boolean;
  /** Get the share URL for this request */
  getShareUrl(): string;
}

/**
 * Request builder for creating secret requests
 */
export declare class SecretRequestCreateRequest {
  message: string;
  description: string;
  secretExpirationHours: number;
  requestExpirationHours: number;
  maximumViews: number;
  emailTo: string;
  emailReply: string;

  /** Set the message for the recipient */
  setMessage(message: string): SecretRequestCreateRequest;
  /** Set the description for internal use */
  setDescription(description: string): SecretRequestCreateRequest;
  /** Set secret expiration time in hours */
  setSecretExpirationHours(hours: number): SecretRequestCreateRequest;
  /** Set request expiration time in hours */
  setRequestExpirationHours(hours: number): SecretRequestCreateRequest;
  /** Set maximum number of views for the secret */
  setMaximumViews(views: number): SecretRequestCreateRequest;
  /** Set email to send the request to */
  setEmailTo(email: string): SecretRequestCreateRequest;
  /** Set email for automatic reply */
  setEmailReply(email: string): SecretRequestCreateRequest;
  /** Validate the request */
  validate(): string[];
  /** Create a static builder instance */
  static builder(): SecretRequestCreateRequest;
}

/**
 * Secret model class
 */
export declare class Secret {
  slug: string;
  description: string;
  message: string;
  creator: string;
  maximumViews: number;
  currentViews: number;
  expiration: Date | null;
  hasPassword: boolean;
  hasAttachments: boolean;
  attachmentsCount: number;
  attachments: any[];
  isExpired: boolean;
  status: string;
  accessUrl: string;
  shareUrl: string;
  captcha: boolean;
  otpType: string | null;
  ipWhitelist: string | null;
  geolocation: string | null;
  createdAt: Date | null;
  updatedAt: Date | null;

  /** Check if the secret is still active */
  isActive(): boolean;
  /** Get remaining views count */
  getRemainingViews(): number;
  /** Get time remaining before expiration */
  getTimeRemaining(): number | null;
  /** Convert to plain object */
  toObject(): any;
}

/**
 * Statistics model class
 */
export declare class Statistics {
  totalSecrets: number;
  activeSecrets: number;
  expiredSecrets: number;
  totalViews: number;
  secretsWithPassword: number;
  secretsCreatedToday: number;
  secretsCreatedThisWeek: number;
  secretsCreatedThisMonth: number;

  /** Get the percentage of password-protected secrets */
  getPasswordProtectionRate(): number;
  /** Get average views per secret */
  getAverageViewsPerSecret(): number;
  /** Convert to plain object */
  toObject(): any;
}

/**
 * Configuration class
 */
export declare class SharokeyConfig {
  token: string | null;
  apiUrl: string;
  timeout: number;
  retries: number;
  defaultExpirationHours: number;
  defaultMaximumViews: number;
  logLevel: string;
  validateSsl: boolean;
  headers: Record<string, string>;

  constructor(options?: SharokeyConfigOptions);
  /** Validate the configuration */
  validate(): string[];
  /** Create a copy of the configuration */
  clone(): SharokeyConfig;
}

/**
 * Request builder for creating secrets
 */
export declare class SecretCreateRequest {
  content: string;
  description: string;
  message: string;
  expirationHours: number;
  maximumViews: number;
  password: string | null;
  captcha: boolean;
  ipWhitelist: string | null;
  geolocation: string | null;
  attachments: AttachmentData[];
  otpEmail: string | null;
  otpPhone: string | null;

  /** Set the secret content */
  setContent(content: string): SecretCreateRequest;
  /** Set the description */
  setDescription(description: string): SecretCreateRequest;
  /** Set the message for the recipient */
  setMessage(message: string): SecretCreateRequest;
  /** Set expiration time in hours */
  setExpirationHours(hours: number): SecretCreateRequest;
  /** Set maximum number of views */
  setMaximumViews(views: number): SecretCreateRequest;
  /** Set password protection */
  setPassword(password: string): SecretCreateRequest;
  /** Add a file attachment */
  addAttachment(name: string, data: Buffer | Uint8Array | ArrayBuffer): SecretCreateRequest;
  /** Set OTP email for additional security */
  setOtpEmail(email: string): SecretCreateRequest;
  /** Set OTP phone for additional security */
  setOtpPhone(phone: string): SecretCreateRequest;
  /** Enable CAPTCHA verification */
  setCaptcha(enabled: boolean): SecretCreateRequest;
  /** Set IP whitelist restrictions */
  setIpWhitelist(ipWhitelist: string): SecretCreateRequest;
  /** Set geolocation restrictions */
  setGeolocation(geolocation: string): SecretCreateRequest;
  /** Validate the request */
  validate(): string[];
  /** Create a static builder instance */
  static builder(): SecretCreateRequest;
}

/**
 * API Error class
 */
export declare class ApiError extends Error {
  status: number;
  response: any;

  constructor(message: string, status: number, response: any);
}

/**
 * Cryptographic service class
 */
export declare class CryptoService {
  /** Generate a random password */
  generatePassword(length?: number, includeSymbols?: boolean): string;
  /** Generate encryption keys */
  generateKeys(): { keyA: string; keyB: string };
  /** Encrypt content */
  encrypt(content: string, keyString: string): Promise<any>;
}

/**
 * API client class
 */
export declare class ApiClient {
  constructor(config: SharokeyConfig);
  /** Test API connectivity */
  testConnectivity(): Promise<boolean>;
}

/**
 * Main Sharokey client class
 */
export declare class SharokeyClient {
  constructor(options?: SharokeyConfigOptions | SharokeyConfig);

  /** Test connectivity to the API */
  testConnection(): Promise<boolean>;
  /** Validate the current token and get user information */
  validateToken(): Promise<any>;
  /** Get current user information */
  getCurrentUser(): any;

  /** Create a new secret */
  createSecret(content: string, options?: SecretCreateOptions): Promise<Secret>;
  createSecret(request: SecretCreateOptions): Promise<Secret>;
  createSecret(request: SecretCreateRequest): Promise<Secret>;

  /** List secrets with optional filtering */
  listSecrets(filters?: SecretListFilters): Promise<ListResponse<Secret>>;
  /** Get details of a specific secret */
  getSecret(slug: string): Promise<Secret>;
  /** Delete a secret */
  deleteSecret(slug: string): Promise<boolean>;
  /** Get usage statistics */
  getStatistics(): Promise<Statistics>;

  /** Generate a random password */
  generatePassword(length?: number, includeSymbols?: boolean): string;
  /** Create a secret with generated password */
  createPasswordSecret(description: string, options?: any): Promise<BatchSecretResult>;
  /** Batch create multiple secrets */
  createBatchSecrets(contents: Array<string | SecretCreateOptions>, defaultOptions?: SecretCreateOptions): Promise<Secret[]>;

  /** Search secrets by description or content */
  searchSecrets(query: string, options?: { limit?: number; status?: string }): Promise<Secret[]>;
  /** Get active secrets */
  getActiveSecrets(limit?: number): Promise<Secret[]>;
  /** Clean up expired secrets */
  cleanupExpiredSecrets(dryRun?: boolean): Promise<CleanupResult>;

  /** Update client configuration */
  updateConfig(newConfig: SharokeyConfigOptions): SharokeyClient;
  /** Get client information */
  getInfo(): ClientInfo;

  /** Create a new secret request */
  createSecretRequest(options?: SecretRequestCreateOptions): Promise<SecretRequest>;
  createSecretRequest(request: SecretRequestCreateRequest): Promise<SecretRequest>;
  /** List secret requests with optional filtering */
  listSecretRequests(filters?: SecretRequestListFilters): Promise<ListResponse<SecretRequest>>;
  /** Get details of a specific secret request */
  getSecretRequest(id: number | string): Promise<SecretRequest>;
  /** Delete a secret request */
  deleteSecretRequest(id: number | string): Promise<boolean>;
  /** Get secret request statistics */
  getSecretRequestStatistics(): Promise<any>;
  /** Get active secret requests */
  getActiveSecretRequests(limit?: number): Promise<SecretRequest[]>;
}

// Main functions
export declare function createClient(options?: SharokeyConfigOptions): SharokeyClient;
export declare function createSecretRequest(): SecretCreateRequest;
export declare function createSecretRequestRequest(): SecretRequestCreateRequest;
export declare function generatePassword(length?: number, includeSymbols?: boolean): string;
export declare function validateConfig(config: SharokeyConfigOptions): string[];

// Export version
export declare const version: string;

// Default export
declare const SharokeyJS: typeof SharokeyClient;
export default SharokeyJS;