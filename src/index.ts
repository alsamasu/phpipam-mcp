#!/usr/bin/env node
/**
 * phpIPAM MCP Server
 * 
 * Model Context Protocol server for phpIPAM IP Address Management.
 * Provides tools for managing sections, subnets, and IP addresses.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';

import { loadConfig, assertWriteEnabled, assertSubnetCreateEnabled, assertSectionCreateEnabled, maskConfig } from './config.js';
import { PhpIpamClient } from './client.js';
import {
  PhpIpamConfig,
  PhpIpamError,
  GetSectionInput,
  ListSubnetsInput,
  GetSubnetInput,
  ListAddressesInput,
  GetAddressInput,
  SearchInput,
  AllocateAddressInput,
  ReleaseAddressInput,
  UpsertAddressInput,
  EnsureSubnetInput,
  EnsureSectionInput,
} from './types.js';

// ============================================================================
// Tool Definitions
// ============================================================================

const TOOLS: Tool[] = [
  // Health Check
  {
    name: 'phpipam.health',
    description: 'Check phpIPAM connectivity and authentication status',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  
  // Sections (Read)
  {
    name: 'phpipam.sections.list',
    description: 'List all sections in phpIPAM',
    inputSchema: {
      type: 'object',
      properties: {},
      required: [],
    },
  },
  {
    name: 'phpipam.sections.get',
    description: 'Get a specific section by ID or name',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Section ID' },
        name: { type: 'string', description: 'Section name (alternative to ID)' },
      },
      required: [],
    },
  },
  
  // Subnets (Read)
  {
    name: 'phpipam.subnets.list',
    description: 'List all subnets in a section',
    inputSchema: {
      type: 'object',
      properties: {
        sectionId: { type: 'string', description: 'Section ID' },
      },
      required: ['sectionId'],
    },
  },
  {
    name: 'phpipam.subnets.get',
    description: 'Get a specific subnet by ID or CIDR notation',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Subnet ID' },
        cidr: { type: 'string', description: 'CIDR notation (e.g., 192.168.1.0/24)' },
      },
      required: [],
    },
  },
  
  // Addresses (Read)
  {
    name: 'phpipam.addresses.list',
    description: 'List all addresses in a subnet',
    inputSchema: {
      type: 'object',
      properties: {
        subnetId: { type: 'string', description: 'Subnet ID' },
      },
      required: ['subnetId'],
    },
  },
  {
    name: 'phpipam.addresses.get',
    description: 'Get a specific address by ID or IP',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Address ID' },
        ip: { type: 'string', description: 'IP address' },
      },
      required: [],
    },
  },
  
  // Search
  {
    name: 'phpipam.search',
    description: 'Search for addresses by IP, hostname, or other criteria',
    inputSchema: {
      type: 'object',
      properties: {
        query: { type: 'string', description: 'Search query (IP, hostname, etc.)' },
        type: {
          type: 'string',
          enum: ['ip', 'hostname', 'mac', 'all'],
          description: 'Type of search (default: all)',
        },
      },
      required: ['query'],
    },
  },
  
  // Addresses (Write) - Guarded by PHPIPAM_WRITE_ENABLED
  {
    name: 'phpipam.addresses.allocate',
    description: 'Allocate the first available IP address in a subnet. Requires PHPIPAM_WRITE_ENABLED=true',
    inputSchema: {
      type: 'object',
      properties: {
        subnetId: { type: 'string', description: 'Subnet ID to allocate from' },
        hostname: { type: 'string', description: 'Hostname for the address' },
        description: { type: 'string', description: 'Description' },
        mac: { type: 'string', description: 'MAC address' },
        owner: { type: 'string', description: 'Owner/responsible person' },
        note: { type: 'string', description: 'Additional notes' },
      },
      required: ['subnetId'],
    },
  },
  {
    name: 'phpipam.addresses.release',
    description: 'Release (delete) an IP address. Requires PHPIPAM_WRITE_ENABLED=true',
    inputSchema: {
      type: 'object',
      properties: {
        id: { type: 'string', description: 'Address ID' },
        ip: { type: 'string', description: 'IP address (alternative to ID)' },
      },
      required: [],
    },
  },
  {
    name: 'phpipam.addresses.upsert',
    description: 'Create or update an IP address. Requires PHPIPAM_WRITE_ENABLED=true',
    inputSchema: {
      type: 'object',
      properties: {
        ip: { type: 'string', description: 'IP address' },
        subnetId: { type: 'string', description: 'Subnet ID' },
        hostname: { type: 'string', description: 'Hostname' },
        description: { type: 'string', description: 'Description' },
        mac: { type: 'string', description: 'MAC address' },
        owner: { type: 'string', description: 'Owner' },
        note: { type: 'string', description: 'Notes' },
      },
      required: ['ip', 'subnetId'],
    },
  },
  
  // Subnet Creation - Guarded by PHPIPAM_ALLOW_SUBNET_CREATE
  {
    name: 'phpipam.subnets.ensure',
    description: 'Ensure a subnet exists (create if missing). Requires PHPIPAM_WRITE_ENABLED=true and PHPIPAM_ALLOW_SUBNET_CREATE=true',
    inputSchema: {
      type: 'object',
      properties: {
        cidr: { type: 'string', description: 'Subnet in CIDR notation (e.g., 192.168.1.0/24)' },
        sectionId: { type: 'string', description: 'Section ID' },
        description: { type: 'string', description: 'Subnet description' },
        vlanId: { type: 'string', description: 'VLAN ID' },
        masterSubnetId: { type: 'string', description: 'Parent subnet ID (for nested subnets)' },
      },
      required: ['cidr', 'sectionId'],
    },
  },
  
  // Section Creation - Guarded by PHPIPAM_ALLOW_SECTION_CREATE
  {
    name: 'phpipam.sections.ensure',
    description: 'Ensure a section exists (create if missing). Requires PHPIPAM_WRITE_ENABLED=true and PHPIPAM_ALLOW_SECTION_CREATE=true',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Section name' },
        description: { type: 'string', description: 'Section description' },
        masterSection: { type: 'string', description: 'Parent section ID' },
      },
      required: ['name'],
    },
  },
];

// ============================================================================
// Tool Handlers
// ============================================================================

async function handleTool(
  name: string,
  args: Record<string, unknown>,
  client: PhpIpamClient,
  config: PhpIpamConfig
): Promise<unknown> {
  switch (name) {
    // Health
    case 'phpipam.health':
      return client.health();
    
    // Sections (Read)
    case 'phpipam.sections.list':
      return client.listSections();
    
    case 'phpipam.sections.get': {
      const input = args as GetSectionInput;
      if (input.id) {
        return client.getSection(input.id);
      }
      if (input.name) {
        const section = await client.getSectionByName(input.name);
        if (!section) {
          throw new PhpIpamError(`Section not found: ${input.name}`, 'NOT_FOUND');
        }
        return section;
      }
      throw new PhpIpamError('Either id or name is required', 'VALIDATION');
    }
    
    // Subnets (Read)
    case 'phpipam.subnets.list': {
      const input = args as ListSubnetsInput;
      return client.listSubnets(input.sectionId);
    }
    
    case 'phpipam.subnets.get': {
      const input = args as GetSubnetInput;
      if (input.id) {
        return client.getSubnet(input.id);
      }
      if (input.cidr) {
        const subnet = await client.getSubnetByCidr(input.cidr);
        if (!subnet) {
          throw new PhpIpamError(`Subnet not found: ${input.cidr}`, 'NOT_FOUND');
        }
        return subnet;
      }
      throw new PhpIpamError('Either id or cidr is required', 'VALIDATION');
    }
    
    // Addresses (Read)
    case 'phpipam.addresses.list': {
      const input = args as ListAddressesInput;
      return client.listAddresses(input.subnetId);
    }
    
    case 'phpipam.addresses.get': {
      const input = args as GetAddressInput;
      if (input.id) {
        return client.getAddress(input.id);
      }
      if (input.ip) {
        const address = await client.getAddressByIp(input.ip);
        if (!address) {
          throw new PhpIpamError(`Address not found: ${input.ip}`, 'NOT_FOUND');
        }
        return address;
      }
      throw new PhpIpamError('Either id or ip is required', 'VALIDATION');
    }
    
    // Search
    case 'phpipam.search': {
      const input = args as SearchInput;
      if (input.type === 'hostname') {
        const addresses = await client.searchByHostname(input.query);
        return { addresses };
      }
      return client.search(input.query);
    }
    
    // Addresses (Write)
    case 'phpipam.addresses.allocate': {
      assertWriteEnabled(config, 'addresses.allocate');
      const input = args as AllocateAddressInput;
      return client.allocateFirstFree(input.subnetId, {
        hostname: input.hostname,
        description: input.description,
        mac: input.mac,
        owner: input.owner,
        note: input.note,
      });
    }
    
    case 'phpipam.addresses.release': {
      assertWriteEnabled(config, 'addresses.release');
      const input = args as ReleaseAddressInput;
      
      let addressId = input.id;
      if (!addressId && input.ip) {
        const address = await client.getAddressByIp(input.ip);
        if (!address) {
          throw new PhpIpamError(`Address not found: ${input.ip}`, 'NOT_FOUND');
        }
        addressId = address.id;
      }
      
      if (!addressId) {
        throw new PhpIpamError('Either id or ip is required', 'VALIDATION');
      }
      
      await client.deleteAddress(addressId);
      return { success: true, message: `Address ${addressId} released` };
    }
    
    case 'phpipam.addresses.upsert': {
      assertWriteEnabled(config, 'addresses.upsert');
      const input = args as UpsertAddressInput;
      
      // Check if address already exists
      const existing = await client.getAddressByIp(input.ip);
      
      if (existing) {
        // Update existing address
        return client.updateAddress(existing.id, {
          hostname: input.hostname,
          description: input.description,
          mac: input.mac,
          owner: input.owner,
          note: input.note,
        });
      } else {
        // Create new address
        return client.createAddress({
          ip: input.ip,
          subnetId: input.subnetId,
          hostname: input.hostname,
          description: input.description,
          mac: input.mac,
          owner: input.owner,
          note: input.note,
        });
      }
    }
    
    // Subnet Creation
    case 'phpipam.subnets.ensure': {
      assertSubnetCreateEnabled(config);
      const input = args as EnsureSubnetInput;
      
      // Check if subnet already exists
      const existing = await client.getSubnetByCidr(input.cidr);
      if (existing) {
        return { ...existing, created: false };
      }
      
      // Parse CIDR
      const [subnet, maskStr] = input.cidr.split('/');
      const mask = maskStr;
      
      const newSubnet = await client.createSubnet({
        subnet,
        mask,
        sectionId: input.sectionId,
        description: input.description,
        vlanId: input.vlanId,
        masterSubnetId: input.masterSubnetId,
      });
      
      return { ...newSubnet, created: true };
    }
    
    // Section Creation
    case 'phpipam.sections.ensure': {
      assertSectionCreateEnabled(config);
      const input = args as EnsureSectionInput;
      
      // Check if section already exists
      const existing = await client.getSectionByName(input.name);
      if (existing) {
        return { ...existing, created: false };
      }
      
      const newSection = await client.createSection({
        name: input.name,
        description: input.description,
        masterSection: input.masterSection,
      });
      
      return { ...newSection, created: true };
    }
    
    default:
      throw new PhpIpamError(`Unknown tool: ${name}`, 'VALIDATION');
  }
}

// ============================================================================
// Main Server
// ============================================================================

async function main(): Promise<void> {
  // Load configuration
  let config: PhpIpamConfig;
  try {
    config = loadConfig();
  } catch (error) {
    if (error instanceof PhpIpamError) {
      console.error(`Configuration error: ${error.message}`);
      process.exit(1);
    }
    throw error;
  }
  
  // Log configuration (with secrets masked)
  console.error('phpIPAM MCP Server starting...');
  console.error('Configuration:', JSON.stringify(maskConfig(config), null, 2));
  
  // Create client
  const client = new PhpIpamClient(config);
  
  // Create MCP server
  const server = new Server(
    {
      name: 'phpipam-mcp',
      version: '0.1.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );
  
  // Handle tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools: TOOLS };
  });
  
  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    
    try {
      const result = await handleTool(name, args as Record<string, unknown>, client, config);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      if (error instanceof PhpIpamError) {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                error: error.code,
                message: error.message,
                retryable: error.retryable,
              }),
            },
          ],
          isError: true,
        };
      }
      
      // Unexpected error
      const message = error instanceof Error ? error.message : 'Unknown error';
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'INTERNAL',
              message,
            }),
          },
        ],
        isError: true,
      };
    }
  });
  
  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);
  
  console.error('phpIPAM MCP Server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
