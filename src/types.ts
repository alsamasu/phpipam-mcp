/**
 * phpIPAM MCP Server Types
 */

// ============================================================================
// Configuration Types
// ============================================================================

export type AuthMode = 'token' | 'password' | 'auto';

export interface PhpIpamConfig {
  baseUrl: string;
  appId: string;
  authMode: AuthMode;
  token?: string;
  username?: string;
  password?: string;
  
  // Feature toggles
  writeEnabled: boolean;
  verifyTls: boolean;
  enableCache: boolean;
  debugHttp: boolean;
  allowSubnetCreate: boolean;
  allowSectionCreate: boolean;
  
  // Timeouts and retries
  timeout: number;
  maxRetries: number;
  retryDelay: number;
}

// ============================================================================
// Error Types
// ============================================================================

export type ErrorCode = 
  | 'AUTH'           // Authentication failure
  | 'VALIDATION'     // Input validation error
  | 'NOT_FOUND'      // Resource not found
  | 'CONFLICT'       // Resource conflict (duplicate, in use)
  | 'RETRYABLE'      // Transient error, can retry
  | 'FORBIDDEN'      // Operation not permitted (toggle disabled)
  | 'INTERNAL';      // Internal server error

export class PhpIpamError extends Error {
  constructor(
    message: string,
    public code: ErrorCode,
    public statusCode?: number,
    public retryable: boolean = false
  ) {
    super(message);
    this.name = 'PhpIpamError';
  }
}

// ============================================================================
// API Response Types
// ============================================================================

export interface ApiResponse<T = unknown> {
  code: number;
  success: boolean;
  data?: T;
  message?: string;
  time?: number;
}

// ============================================================================
// phpIPAM Entity Types
// ============================================================================

export interface Section {
  id: string;
  name: string;
  description?: string;
  masterSection?: string;
  permissions?: string;
  strictMode?: string;
  subnetOrdering?: string;
  order?: string;
  showVLAN?: string;
  showVRF?: string;
  showSupernetOnly?: string;
  DNS?: string;
}

export interface Subnet {
  id: string;
  subnet: string;
  mask: string;
  sectionId: string;
  description?: string;
  vrfId?: string;
  masterSubnetId?: string;
  allowRequests?: string;
  vlanId?: string;
  showName?: string;
  permissions?: string;
  DNSrecursive?: string;
  DNSrecords?: string;
  nameserverId?: string;
  scanAgent?: string;
  isFolder?: string;
  isFull?: string;
  tag?: string;
  threshold?: string;
  location?: string;
  editDate?: string;
  gateway?: {
    ip_addr: string;
  };
  calculation?: {
    Type: string;
    'IP address': string;
    Network: string;
    Broadcast: string;
    Subnet: string;
    hosts: number;
    used: number;
    free: number;
    freehosts_percent: number;
    Used_percent: number;
  };
}

export interface Address {
  id: string;
  subnetId: string;
  ip: string;
  is_gateway?: string;
  description?: string;
  hostname?: string;
  mac?: string;
  owner?: string;
  tag?: string;
  deviceId?: string;
  port?: string;
  note?: string;
  lastSeen?: string;
  excludePing?: string;
  PTRignore?: string;
  PTR?: string;
  firewallAddressObject?: string;
  editDate?: string;
}

export interface Vlan {
  id: string;
  domainId: string;
  name: string;
  number: string;
  description?: string;
}

export interface Device {
  id: string;
  hostname: string;
  ip_addr?: string;
  description?: string;
  type?: string;
  vendor?: string;
  model?: string;
  location?: string;
}

export interface SearchResult {
  addresses?: Address[];
  subnets?: Subnet[];
}

// ============================================================================
// Tool Input Types
// ============================================================================

export interface ListSectionsInput {
  // No required parameters
}

export interface GetSectionInput {
  id?: string;
  name?: string;
}

export interface ListSubnetsInput {
  sectionId: string;
}

export interface GetSubnetInput {
  id?: string;
  cidr?: string; // e.g., "192.168.1.0/24"
}

export interface ListAddressesInput {
  subnetId: string;
}

export interface GetAddressInput {
  id?: string;
  ip?: string;
}

export interface SearchInput {
  query: string;
  type?: 'ip' | 'hostname' | 'mac' | 'all';
}

export interface AllocateAddressInput {
  subnetId: string;
  hostname?: string;
  description?: string;
  mac?: string;
  owner?: string;
  note?: string;
}

export interface ReleaseAddressInput {
  id?: string;
  ip?: string;
}

export interface UpsertAddressInput {
  ip: string;
  subnetId: string;
  hostname?: string;
  description?: string;
  mac?: string;
  owner?: string;
  note?: string;
}

export interface EnsureSubnetInput {
  cidr: string;
  sectionId: string;
  description?: string;
  vlanId?: string;
  masterSubnetId?: string;
}

export interface EnsureSectionInput {
  name: string;
  description?: string;
  masterSection?: string;
}
