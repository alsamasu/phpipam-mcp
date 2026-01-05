/**
 * phpIPAM API Client
 * 
 * Handles all HTTP communication with the phpIPAM API.
 * Supports both token and password authentication.
 * Supports encrypted (Crypt) mode for secure API communication.
 */

import https from 'node:https';
import crypto from 'node:crypto';
import {
  PhpIpamConfig,
  PhpIpamError,
  ApiResponse,
  Section,
  Subnet,
  Address,
  SearchResult,
} from './types.js';
import { getEffectiveAuthMode } from './config.js';

interface RequestOptions {
  method: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  path: string;
  body?: Record<string, unknown>;
  retryCount?: number;
}

interface AuthResponseData {
  token: string;
  expires?: string;
}

/**
 * Encrypt data using Rijndael-256 ECB mode (phpIPAM's "Crypt" security)
 * Note: Rijndael-256 with 256-bit blocks is not standard AES.
 * phpIPAM uses mcrypt's RIJNDAEL_256 which has 256-bit block size.
 * We'll use AES-256-ECB as a fallback since Node.js doesn't support Rijndael-256.
 */
function encryptRequest(data: string, key: string): string {
  // Pad key to 32 bytes (256 bits)
  const keyBuffer = Buffer.alloc(32);
  Buffer.from(key).copy(keyBuffer);
  
  // Use AES-256-ECB (closest to Rijndael-256 in Node.js)
  const cipher = crypto.createCipheriv('aes-256-ecb', keyBuffer, null);
  cipher.setAutoPadding(true);
  
  let encrypted = cipher.update(data, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  
  return encodeURIComponent(encrypted);
}

/**
 * Simple in-memory cache
 */
class SimpleCache {
  private cache = new Map<string, { data: unknown; expires: number }>();
  private ttl: number;
  
  constructor(ttlMs: number = 60000) {
    this.ttl = ttlMs;
  }
  
  get<T>(key: string): T | undefined {
    const entry = this.cache.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expires) {
      this.cache.delete(key);
      return undefined;
    }
    return entry.data as T;
  }
  
  set(key: string, data: unknown): void {
    this.cache.set(key, { data, expires: Date.now() + this.ttl });
  }
  
  clear(): void {
    this.cache.clear();
  }
}

export class PhpIpamClient {
  private config: PhpIpamConfig;
  private authToken: string | null = null;
  private tokenExpires: number = 0;
  private cache: SimpleCache;
  private httpsAgent: https.Agent;
  private useCrypt: boolean;
  
  constructor(config: PhpIpamConfig) {
    this.config = config;
    this.cache = new SimpleCache(60000); // 1 minute cache
    this.httpsAgent = new https.Agent({
      rejectUnauthorized: config.verifyTls,
    });
    // Use crypt mode when token auth is configured
    this.useCrypt = getEffectiveAuthMode(config) === 'token';
  }
  
  /**
   * Get authentication token (handles both token and password auth)
   */
  private async getAuthToken(): Promise<string> {
    const effectiveMode = getEffectiveAuthMode(this.config);
    
    // Token authentication - use the static token directly
    if (effectiveMode === 'token') {
      return this.config.token!;
    }
    
    // Password authentication - check if we have a valid session token
    if (this.authToken && Date.now() < this.tokenExpires) {
      return this.authToken;
    }
    
    // Authenticate and get session token
    const authUrl = `${this.config.baseUrl}/api/${this.config.appId}/user/`;
    const auth = Buffer.from(
      `${this.config.username}:${this.config.password}`
    ).toString('base64');
    
    const response = await this.httpRequest({
      method: 'POST',
      url: authUrl,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type': 'application/json',
      },
    });
    
    const authData = response.data as AuthResponseData | undefined;
    if (!response.success || !authData?.token) {
      throw new PhpIpamError(
        `Authentication failed: ${response.message || 'Unknown error'}`,
        'AUTH',
        response.code
      );
    }
    
    this.authToken = authData.token;
    // Token typically expires in 6 hours, refresh after 5
    this.tokenExpires = Date.now() + (5 * 60 * 60 * 1000);
    
    return this.authToken;
  }
  
  /**
   * Make HTTP request with retry logic
   */
  private async httpRequest(options: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  }): Promise<ApiResponse> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(options.url);
      
      const requestOptions: https.RequestOptions = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: options.method,
        headers: options.headers,
        agent: urlObj.protocol === 'https:' ? this.httpsAgent : undefined,
        timeout: this.config.timeout,
      };
      
      if (this.config.debugHttp) {
        console.error(`[HTTP] ${options.method} ${options.url}`);
        if (options.body) {
          console.error(`[HTTP] Body: ${options.body}`);
        }
      }
      
      const protocol = urlObj.protocol === 'https:' ? https : require('http');
      
      const req = protocol.request(requestOptions, (res: any) => {
        let data = '';
        
        res.on('data', (chunk: Buffer) => {
          data += chunk.toString();
        });
        
        res.on('end', () => {
          try {
            if (this.config.debugHttp) {
              console.error(`[HTTP] Response ${res.statusCode}: ${data.substring(0, 500)}`);
            }
            
            const parsed = JSON.parse(data) as ApiResponse;
            resolve(parsed);
          } catch {
            resolve({
              code: res.statusCode,
              success: false,
              message: `Failed to parse response: ${data.substring(0, 200)}`,
            });
          }
        });
      });
      
      req.on('error', (error: Error) => {
        reject(new PhpIpamError(
          `HTTP request failed: ${error.message}`,
          'RETRYABLE',
          undefined,
          true
        ));
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new PhpIpamError(
          'Request timeout',
          'RETRYABLE',
          undefined,
          true
        ));
      });
      
      if (options.body) {
        req.write(options.body);
      }
      
      req.end();
    });
  }
  
  /**
   * Make authenticated API request
   */
  async request<T>(options: RequestOptions): Promise<T> {
    const { method, path, body, retryCount = 0 } = options;
    const token = await this.getAuthToken();
    
    let url: string;
    let headers: Record<string, string>;
    let requestBody: string | undefined;
    
    if (this.useCrypt) {
      // Crypt mode: encrypt the request parameters
      const controller = path.split('/').filter(p => p)[0] || '';
      const requestParams: Record<string, unknown> = {
        controller: controller,
      };
      
      // Parse path to extract controller and id
      const pathParts = path.split('/').filter(p => p);
      if (pathParts.length > 1) {
        requestParams.id = pathParts[1];
      }
      
      // Add body params for write operations
      if (body) {
        Object.assign(requestParams, body);
      }
      
      const encryptedRequest = encryptRequest(JSON.stringify(requestParams), token);
      url = `${this.config.baseUrl}/api/${this.config.appId}/?enc_request=${encryptedRequest}`;
      
      headers = {
        'Content-Type': 'application/json',
      };
      
      // For non-GET requests, we need to indicate the method
      if (method !== 'GET') {
        // phpIPAM crypt mode uses query params, method is determined by request
        // We'll try sending as the actual HTTP method
      }
    } else {
      // Standard mode: use token in header
      url = `${this.config.baseUrl}/api/${this.config.appId}${path}`;
      headers = {
        'Content-Type': 'application/json',
        'token': token,
      };
      requestBody = body ? JSON.stringify(body) : undefined;
    }
    
    try {
      const response = await this.httpRequest({
        method: this.useCrypt ? 'GET' : method, // Crypt mode uses GET with encrypted params
        url,
        headers,
        body: this.useCrypt ? undefined : requestBody,
      });
      
      if (!response.success) {
        const error = this.mapApiError(response);
        
        // Retry on transient errors
        if (error.retryable && retryCount < this.config.maxRetries) {
          const delay = this.config.retryDelay * Math.pow(2, retryCount);
          await this.sleep(delay);
          return this.request({ ...options, retryCount: retryCount + 1 });
        }
        
        throw error;
      }
      
      return response.data as T;
    } catch (error) {
      if (error instanceof PhpIpamError) {
        // Retry on retryable errors
        if (error.retryable && retryCount < this.config.maxRetries) {
          const delay = this.config.retryDelay * Math.pow(2, retryCount);
          await this.sleep(delay);
          return this.request({ ...options, retryCount: retryCount + 1 });
        }
        throw error;
      }
      throw new PhpIpamError(
        `Unexpected error: ${error}`,
        'INTERNAL'
      );
    }
  }
  
  /**
   * Map API response to appropriate error
   */
  private mapApiError(response: ApiResponse): PhpIpamError {
    const code = response.code;
    const message = response.message || 'Unknown error';
    
    if (code === 401) {
      // Clear cached auth token on auth failure
      this.authToken = null;
      return new PhpIpamError(message, 'AUTH', code);
    }
    
    if (code === 403) {
      return new PhpIpamError(message, 'FORBIDDEN', code);
    }
    
    if (code === 404) {
      return new PhpIpamError(message, 'NOT_FOUND', code);
    }
    
    if (code === 409) {
      return new PhpIpamError(message, 'CONFLICT', code);
    }
    
    if (code >= 500) {
      return new PhpIpamError(message, 'RETRYABLE', code, true);
    }
    
    return new PhpIpamError(message, 'VALIDATION', code);
  }
  
  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  // =========================================================================
  // Health Check
  // =========================================================================
  
  async health(): Promise<{ healthy: boolean; message: string }> {
    try {
      // Make an actual API call to verify full connectivity
      await this.listSections();
      return { healthy: true, message: 'Connected to phpIPAM' };
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Unknown error';
      return { healthy: false, message };
    }
  }
  
  // =========================================================================
  // Sections
  // =========================================================================
  
  async listSections(): Promise<Section[]> {
    if (this.config.enableCache) {
      const cached = this.cache.get<Section[]>('sections');
      if (cached) return cached;
    }
    
    const sections = await this.request<Section[]>({
      method: 'GET',
      path: '/sections/',
    });
    
    if (this.config.enableCache) {
      this.cache.set('sections', sections);
    }
    
    return sections || [];
  }
  
  async getSection(id: string): Promise<Section> {
    return this.request<Section>({
      method: 'GET',
      path: `/sections/${id}/`,
    });
  }
  
  async getSectionByName(name: string): Promise<Section | null> {
    const sections = await this.listSections();
    return sections.find(s => s.name.toLowerCase() === name.toLowerCase()) || null;
  }
  
  async createSection(data: Partial<Section>): Promise<Section> {
    const result = await this.request<{ id: string }>({
      method: 'POST',
      path: '/sections/',
      body: data as Record<string, unknown>,
    });
    return this.getSection(result.id);
  }
  
  // =========================================================================
  // Subnets
  // =========================================================================
  
  async listSubnets(sectionId: string): Promise<Subnet[]> {
    const cacheKey = `subnets:${sectionId}`;
    if (this.config.enableCache) {
      const cached = this.cache.get<Subnet[]>(cacheKey);
      if (cached) return cached;
    }
    
    try {
      const subnets = await this.request<Subnet[]>({
        method: 'GET',
        path: `/sections/${sectionId}/subnets/`,
      });
      
      if (this.config.enableCache) {
        this.cache.set(cacheKey, subnets);
      }
      
      return subnets || [];
    } catch (error) {
      if (error instanceof PhpIpamError && error.code === 'NOT_FOUND') {
        return [];
      }
      throw error;
    }
  }
  
  async getSubnet(id: string): Promise<Subnet> {
    return this.request<Subnet>({
      method: 'GET',
      path: `/subnets/${id}/`,
    });
  }
  
  async getSubnetByCidr(cidr: string): Promise<Subnet | null> {
    try {
      const result = await this.request<Subnet[]>({
        method: 'GET',
        path: `/subnets/cidr/${encodeURIComponent(cidr)}/`,
      });
      return result && result.length > 0 ? result[0] : null;
    } catch (error) {
      if (error instanceof PhpIpamError && error.code === 'NOT_FOUND') {
        return null;
      }
      throw error;
    }
  }
  
  async createSubnet(data: Partial<Subnet>): Promise<Subnet> {
    const result = await this.request<{ id: string }>({
      method: 'POST',
      path: '/subnets/',
      body: data as Record<string, unknown>,
    });
    return this.getSubnet(result.id);
  }
  
  // =========================================================================
  // Addresses
  // =========================================================================
  
  async listAddresses(subnetId: string): Promise<Address[]> {
    try {
      const addresses = await this.request<Address[]>({
        method: 'GET',
        path: `/subnets/${subnetId}/addresses/`,
      });
      return addresses || [];
    } catch (error) {
      if (error instanceof PhpIpamError && error.code === 'NOT_FOUND') {
        return [];
      }
      throw error;
    }
  }
  
  async getAddress(id: string): Promise<Address> {
    return this.request<Address>({
      method: 'GET',
      path: `/addresses/${id}/`,
    });
  }
  
  async getAddressByIp(ip: string): Promise<Address | null> {
    try {
      const result = await this.request<Address[]>({
        method: 'GET',
        path: `/addresses/search/${encodeURIComponent(ip)}/`,
      });
      return result && result.length > 0 ? result[0] : null;
    } catch (error) {
      if (error instanceof PhpIpamError && error.code === 'NOT_FOUND') {
        return null;
      }
      throw error;
    }
  }
  
  async allocateFirstFree(subnetId: string, data: Partial<Address>): Promise<Address> {
    const result = await this.request<{ id: string }>({
      method: 'POST',
      path: `/addresses/first_free/${subnetId}/`,
      body: data as Record<string, unknown>,
    });
    return this.getAddress(result.id);
  }
  
  async createAddress(data: Partial<Address>): Promise<Address> {
    const result = await this.request<{ id: string }>({
      method: 'POST',
      path: '/addresses/',
      body: data as Record<string, unknown>,
    });
    return this.getAddress(result.id);
  }
  
  async updateAddress(id: string, data: Partial<Address>): Promise<Address> {
    await this.request<void>({
      method: 'PATCH',
      path: `/addresses/${id}/`,
      body: data as Record<string, unknown>,
    });
    return this.getAddress(id);
  }
  
  async deleteAddress(id: string): Promise<void> {
    await this.request<void>({
      method: 'DELETE',
      path: `/addresses/${id}/`,
    });
  }
  
  // =========================================================================
  // Search
  // =========================================================================
  
  async search(query: string): Promise<SearchResult> {
    try {
      const addresses = await this.request<Address[]>({
        method: 'GET',
        path: `/addresses/search/${encodeURIComponent(query)}/`,
      });
      return { addresses: addresses || [] };
    } catch (error) {
      if (error instanceof PhpIpamError && error.code === 'NOT_FOUND') {
        return { addresses: [] };
      }
      throw error;
    }
  }
  
  async searchByHostname(hostname: string): Promise<Address[]> {
    try {
      const result = await this.request<Address[]>({
        method: 'GET',
        path: `/addresses/search_hostname/${encodeURIComponent(hostname)}/`,
      });
      return result || [];
    } catch (error) {
      if (error instanceof PhpIpamError && error.code === 'NOT_FOUND') {
        return [];
      }
      throw error;
    }
  }
}
