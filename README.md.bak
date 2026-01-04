# phpIPAM MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for [phpIPAM](https://phpipam.net/) IP Address Management. This server enables LLMs to manage IP addresses, subnets, and network sections through natural language.

## Features

- **Full IPAM Operations**: List, search, allocate, and release IP addresses
- **Subnet Management**: View and create subnets with proper CIDR validation
- **Section Organization**: Manage phpIPAM sections for logical grouping
- **Dual Authentication**: Supports both API token and username/password authentication
- **Security First**: Write operations disabled by default with granular toggles
- **Retry Logic**: Automatic retry with exponential backoff for transient errors
- **Docker Ready**: Minimal container image with non-root user

## Quick Start

### Docker (Recommended)

```bash
docker run -i --rm \
  -e PHPIPAM_BASE_URL=https://phpipam.example.com \
  -e PHPIPAM_APP_ID=myapp \
  -e PHPIPAM_TOKEN=your-api-token \
  mcp/phpipam-mcp
```

### From Source

```bash
# Clone the repository
git clone https://github.com/alsamasu/phpipam-mcp.git
cd phpipam-mcp

# Install dependencies
npm install

# Build
npm run build

# Run (with environment variables set)
node dist/index.js
```

## Configuration

All configuration is done through environment variables:

### Required Settings

| Variable | Description | Example |
|----------|-------------|---------|
| `PHPIPAM_BASE_URL` | Base URL of phpIPAM instance | `https://phpipam.example.com` |
| `PHPIPAM_APP_ID` | API application ID | `myapp` |

### Authentication

The server supports two authentication methods. Use `PHPIPAM_AUTH_MODE` to select:

#### Token Authentication (Recommended)

```bash
PHPIPAM_AUTH_MODE=token
PHPIPAM_TOKEN=your-api-token
```

Generate an API token in phpIPAM: Admin > API > Your App > Security > Token

#### Username/Password Authentication

```bash
PHPIPAM_AUTH_MODE=password
PHPIPAM_USERNAME=admin
PHPIPAM_PASSWORD=your-password
```

#### Auto Mode (Default)

```bash
PHPIPAM_AUTH_MODE=auto
# Provide either token OR username/password
# Token takes precedence if both are provided
```

### Feature Toggles

All write operations are **disabled by default** for security:

| Variable | Default | Description |
|----------|---------|-------------|
| `PHPIPAM_WRITE_ENABLED` | `false` | Enable write operations (allocate, release, upsert) |
| `PHPIPAM_VERIFY_TLS` | `true` | Verify TLS certificates |
| `PHPIPAM_ENABLE_CACHE` | `false` | Cache API responses (60s TTL) |
| `PHPIPAM_DEBUG_HTTP` | `false` | Log HTTP request/response details |
| `PHPIPAM_ALLOW_SUBNET_CREATE` | `false` | Allow subnet creation via `subnets.ensure` |
| `PHPIPAM_ALLOW_SECTION_CREATE` | `false` | Allow section creation via `sections.ensure` |

### Performance Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `PHPIPAM_TIMEOUT` | `30000` | Request timeout in milliseconds |
| `PHPIPAM_MAX_RETRIES` | `3` | Maximum retry attempts |
| `PHPIPAM_RETRY_DELAY` | `1000` | Base retry delay in milliseconds |

## Available Tools

### Read Operations (Always Available)

| Tool | Description |
|------|-------------|
| `phpipam.health` | Check connectivity and authentication |
| `phpipam.sections.list` | List all sections |
| `phpipam.sections.get` | Get section by ID or name |
| `phpipam.subnets.list` | List subnets in a section |
| `phpipam.subnets.get` | Get subnet by ID or CIDR |
| `phpipam.addresses.list` | List addresses in a subnet |
| `phpipam.addresses.get` | Get address by ID or IP |
| `phpipam.search` | Search by IP, hostname, or MAC |

### Write Operations (Require `PHPIPAM_WRITE_ENABLED=true`)

| Tool | Description |
|------|-------------|
| `phpipam.addresses.allocate` | Allocate first free IP in subnet |
| `phpipam.addresses.release` | Release (delete) an IP address |
| `phpipam.addresses.upsert` | Create or update an IP address |

### Create Operations (Require Additional Toggles)

| Tool | Required Toggle | Description |
|------|-----------------|-------------|
| `phpipam.subnets.ensure` | `PHPIPAM_ALLOW_SUBNET_CREATE=true` | Create subnet if not exists |
| `phpipam.sections.ensure` | `PHPIPAM_ALLOW_SECTION_CREATE=true` | Create section if not exists |

## MCP Client Configuration

### Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "phpipam": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "PHPIPAM_BASE_URL=https://phpipam.example.com",
        "-e", "PHPIPAM_APP_ID=myapp",
        "-e", "PHPIPAM_TOKEN=your-token",
        "mcp/phpipam-mcp"
      ]
    }
  }
}
```

### With Write Operations Enabled

```json
{
  "mcpServers": {
    "phpipam": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "PHPIPAM_BASE_URL=https://phpipam.example.com",
        "-e", "PHPIPAM_APP_ID=myapp",
        "-e", "PHPIPAM_TOKEN=your-token",
        "-e", "PHPIPAM_WRITE_ENABLED=true",
        "mcp/phpipam-mcp"
      ]
    }
  }
}
```

## Common Workflows

### Lookup and Allocate IP

1. Search for existing assignment: `phpipam.search { "query": "webserver01" }`
2. Find available subnet: `phpipam.subnets.list { "sectionId": "1" }`
3. Allocate IP: `phpipam.addresses.allocate { "subnetId": "5", "hostname": "webserver01" }`

### Audit IP Usage

1. List sections: `phpipam.sections.list`
2. List subnets: `phpipam.subnets.list { "sectionId": "1" }`
3. View addresses: `phpipam.addresses.list { "subnetId": "5" }`

### Release IP

1. Find the IP: `phpipam.addresses.get { "ip": "192.168.1.50" }`
2. Release it: `phpipam.addresses.release { "ip": "192.168.1.50" }`

## Error Handling

The server returns structured errors with these codes:

| Code | Description | Retryable |
|------|-------------|-----------|
| `AUTH` | Authentication failure | No |
| `VALIDATION` | Invalid input parameters | No |
| `NOT_FOUND` | Resource not found | No |
| `CONFLICT` | Resource conflict (duplicate) | No |
| `FORBIDDEN` | Operation not permitted (toggle disabled) | No |
| `RETRYABLE` | Transient error (timeout, 5xx) | Yes |
| `INTERNAL` | Unexpected server error | No |

## Security Considerations

1. **Read-Only by Default**: Write operations require explicit opt-in
2. **Granular Permissions**: Subnet/section creation have separate toggles
3. **TLS Verification**: Enabled by default, only disable for development
4. **No Secret Logging**: Credentials are never logged (even with debug enabled)
5. **Non-Root Container**: Docker image runs as unprivileged user
6. **Bounded Retries**: Maximum 3 retries with exponential backoff

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run dev

# Run linter
npm run lint

# Run tests
npm test

# Build for production
npm run build
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Related Projects

- [phpIPAM](https://phpipam.net/) - Open source IP address management
- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol for LLM tool integration
- [Docker MCP Catalog](https://hub.docker.com/mcp) - Docker's MCP server registry
