/**
 * Configuration management for phpIPAM MCP Server
 * 
 * Supports two authentication modes:
 * - Token: API token-based authentication
 * - Password: Username/password authentication
 * 
 * Auto mode will detect which credentials are provided and use the appropriate method.
 * If both are provided, token authentication takes precedence.
 */

import { PhpIpamConfig, AuthMode, PhpIpamError } from './types.js';

/**
 * Parse boolean from environment variable
 */
function parseBool(value: string | undefined, defaultValue: boolean): boolean {
  if (value === undefined || value === '') return defaultValue;
  return value.toLowerCase() === 'true' || value === '1';
}

/**
 * Parse integer from environment variable
 */
function parseInt(value: string | undefined, defaultValue: number): number {
  if (value === undefined || value === '') return defaultValue;
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? defaultValue : parsed;
}

/**
 * Load configuration from environment variables
 */
export function loadConfig(): PhpIpamConfig {
  const baseUrl = process.env.PHPIPAM_BASE_URL;
  const appId = process.env.PHPIPAM_APP_ID;
  
  if (!baseUrl) {
    throw new PhpIpamError(
      'PHPIPAM_BASE_URL is required. Set the base URL of your phpIPAM instance (e.g., https://phpipam.example.com)',
      'VALIDATION'
    );
  }
  
  if (!appId) {
    throw new PhpIpamError(
      'PHPIPAM_APP_ID is required. Set the API application ID configured in phpIPAM',
      'VALIDATION'
    );
  }
  
  const authMode = (process.env.PHPIPAM_AUTH_MODE || 'auto') as AuthMode;
  const token = process.env.PHPIPAM_TOKEN;
  const username = process.env.PHPIPAM_USERNAME;
  const password = process.env.PHPIPAM_PASSWORD;
  
  // Validate auth configuration
  validateAuthConfig(authMode, token, username, password);
  
  return {
    baseUrl: baseUrl.replace(/\/$/, ''), // Remove trailing slash
    appId,
    authMode,
    token,
    username,
    password,
    
    // Feature toggles with secure defaults
    writeEnabled: parseBool(process.env.PHPIPAM_WRITE_ENABLED, false),
    verifyTls: parseBool(process.env.PHPIPAM_VERIFY_TLS, true),
    enableCache: parseBool(process.env.PHPIPAM_ENABLE_CACHE, false),
    debugHttp: parseBool(process.env.PHPIPAM_DEBUG_HTTP, false),
    allowSubnetCreate: parseBool(process.env.PHPIPAM_ALLOW_SUBNET_CREATE, false),
    allowSectionCreate: parseBool(process.env.PHPIPAM_ALLOW_SECTION_CREATE, false),
    
    // Timeouts and retries
    timeout: parseInt(process.env.PHPIPAM_TIMEOUT, 30000),
    maxRetries: parseInt(process.env.PHPIPAM_MAX_RETRIES, 3),
    retryDelay: parseInt(process.env.PHPIPAM_RETRY_DELAY, 1000),
  };
}

/**
 * Validate authentication configuration
 */
function validateAuthConfig(
  authMode: AuthMode,
  token?: string,
  username?: string,
  password?: string
): void {
  const hasToken = Boolean(token);
  const hasPassword = Boolean(username && password);
  
  switch (authMode) {
    case 'token':
      if (!hasToken) {
        throw new PhpIpamError(
          'PHPIPAM_TOKEN is required when PHPIPAM_AUTH_MODE=token',
          'VALIDATION'
        );
      }
      break;
      
    case 'password':
      if (!hasPassword) {
        throw new PhpIpamError(
          'PHPIPAM_USERNAME and PHPIPAM_PASSWORD are required when PHPIPAM_AUTH_MODE=password',
          'VALIDATION'
        );
      }
      break;
      
    case 'auto':
      if (!hasToken && !hasPassword) {
        throw new PhpIpamError(
          'Authentication credentials required. Provide either:\n' +
          '  - PHPIPAM_TOKEN for token authentication, or\n' +
          '  - PHPIPAM_USERNAME and PHPIPAM_PASSWORD for password authentication',
          'VALIDATION'
        );
      }
      break;
      
    default:
      throw new PhpIpamError(
        `Invalid PHPIPAM_AUTH_MODE: ${authMode}. Must be 'token', 'password', or 'auto'`,
        'VALIDATION'
      );
  }
}

/**
 * Determine the effective authentication mode
 */
export function getEffectiveAuthMode(config: PhpIpamConfig): 'token' | 'password' {
  if (config.authMode === 'token') return 'token';
  if (config.authMode === 'password') return 'password';
  
  // Auto mode: prefer token if available
  if (config.token) return 'token';
  return 'password';
}

/**
 * Check if a write operation is allowed
 */
export function assertWriteEnabled(config: PhpIpamConfig, operation: string): void {
  if (!config.writeEnabled) {
    throw new PhpIpamError(
      `Write operation '${operation}' is disabled. Set PHPIPAM_WRITE_ENABLED=true to enable write operations.`,
      'FORBIDDEN'
    );
  }
}

/**
 * Check if subnet creation is allowed
 */
export function assertSubnetCreateEnabled(config: PhpIpamConfig): void {
  assertWriteEnabled(config, 'subnets.ensure');
  if (!config.allowSubnetCreate) {
    throw new PhpIpamError(
      'Subnet creation is disabled. Set PHPIPAM_ALLOW_SUBNET_CREATE=true to enable.',
      'FORBIDDEN'
    );
  }
}

/**
 * Check if section creation is allowed
 */
export function assertSectionCreateEnabled(config: PhpIpamConfig): void {
  assertWriteEnabled(config, 'sections.ensure');
  if (!config.allowSectionCreate) {
    throw new PhpIpamError(
      'Section creation is disabled. Set PHPIPAM_ALLOW_SECTION_CREATE=true to enable.',
      'FORBIDDEN'
    );
  }
}

/**
 * Mask sensitive values for logging
 */
export function maskConfig(config: PhpIpamConfig): Record<string, unknown> {
  return {
    baseUrl: config.baseUrl,
    appId: config.appId,
    authMode: config.authMode,
    token: config.token ? '***REDACTED***' : undefined,
    username: config.username,
    password: config.password ? '***REDACTED***' : undefined,
    writeEnabled: config.writeEnabled,
    verifyTls: config.verifyTls,
    enableCache: config.enableCache,
    debugHttp: config.debugHttp,
    allowSubnetCreate: config.allowSubnetCreate,
    allowSectionCreate: config.allowSectionCreate,
    timeout: config.timeout,
    maxRetries: config.maxRetries,
    retryDelay: config.retryDelay,
  };
}
