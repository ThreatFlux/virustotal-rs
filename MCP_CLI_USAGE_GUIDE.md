# VirusTotal CLI - MCP Server Usage Guide

This guide covers how to use the integrated MCP (Model Context Protocol) server functionality within the VirusTotal CLI (`vt-cli`).

## Table of Contents

- [Overview](#overview)
- [Installation](#installation)
- [Basic Usage](#basic-usage)
- [STDIO Mode](#stdio-mode)
- [HTTP Mode](#http-mode)
- [Authentication](#authentication)
- [Environment Variables](#environment-variables)
- [Common Use Cases](#common-use-cases)
- [Troubleshooting](#troubleshooting)
- [Integration Examples](#integration-examples)

## Overview

The VirusTotal CLI provides integrated MCP server functionality, allowing you to expose VirusTotal threat intelligence tools to AI/LLM applications through the Model Context Protocol. This enables language models to securely access VirusTotal data for threat analysis and security research.

### Available MCP Tools

When running as an MCP server, the CLI exposes these tools to connected clients:

- `vt_file_scan` - Analyze files by hash or upload
- `vt_url_scan` - Analyze URLs for threats
- `vt_domain_info` - Get domain reputation and information
- `vt_ip_info` - Get IP address reputation and information
- `vt_search` - VirusTotal Intelligence search (Premium only)
- `vt_livehunt` - Manage hunting rules (Premium only)

## Installation

### Prerequisites

- Rust 1.85.0 or later
- VirusTotal API key (get from [VirusTotal](https://www.virustotal.com/gui/join-us))

### Install from Source

Choose the feature set that matches your needs:

```bash
# Basic CLI with MCP support
cargo install virustotal-rs --features cli-mcp

# CLI with MCP and JWT authentication
cargo install virustotal-rs --features cli-mcp-jwt

# CLI with MCP and OAuth 2.1 authentication  
cargo install virustotal-rs --features cli-mcp-oauth

# All features (recommended for development)
cargo install virustotal-rs --all-features
```

### Pre-built Binaries

Download pre-built binaries from the [releases page](https://github.com/threatflux/virustotal-rs/releases). Choose the appropriate binary for your platform and ensure it's built with MCP features.

## Basic Usage

The MCP functionality is accessed through the `vt-cli mcp` subcommand:

```bash
vt-cli mcp --help
```

### Required Configuration

You must provide a VirusTotal API key either via:

1. **Command line argument**: `--api-key YOUR_KEY`
2. **Environment variable**: `VIRUSTOTAL_API_KEY=YOUR_KEY`

### API Tier Configuration

Specify your VirusTotal API tier:

- `--tier public` (default) - Free tier with rate limits
- `--tier premium` - Premium tier with higher limits and additional features

## STDIO Mode

STDIO mode is recommended for local usage and direct integration with MCP Inspector.

### Basic STDIO Usage

```bash
# Start STDIO server with API key
vt-cli mcp stdio --api-key your_api_key

# Using environment variable
VIRUSTOTAL_API_KEY=your_api_key vt-cli mcp stdio

# With premium tier
vt-cli mcp stdio --api-key your_api_key --tier premium

# With verbose logging
vt-cli --verbose mcp stdio --api-key your_api_key
```

### Connect with MCP Inspector

```bash
# Test the server using MCP Inspector
npx @modelcontextprotocol/inspector vt-cli mcp stdio --api-key your_api_key
```

### Integration with Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "vt-cli",
      "args": ["mcp", "stdio"],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_api_key_here",
        "VIRUSTOTAL_API_TIER": "premium"
      }
    }
  }
}
```

## HTTP Mode

HTTP mode allows remote access to the MCP server and is suitable for web-based integrations.

### Basic HTTP Usage

```bash
# Default address (127.0.0.1:3000)
vt-cli mcp http --api-key your_api_key

# Custom address
vt-cli mcp http --api-key your_api_key --addr 0.0.0.0:8080

# Bind to specific interface
vt-cli mcp http --api-key your_api_key --addr 192.168.1.100:3000
```

### Health Check

Once running, you can verify the server is operational:

```bash
# Check server health
curl http://localhost:3000/health

# Expected response: {"status": "ok"}
```

### Connect with MCP Inspector

```bash
# Connect to HTTP server
npx @modelcontextprotocol/inspector http://localhost:3000
```

## Authentication

The CLI supports multiple authentication methods for HTTP mode.

### JWT Authentication

Requires the `cli-mcp-jwt` feature:

```bash
# Generate a JWT secret (use a secure random string in production)
export JWT_SECRET="your-secure-jwt-secret-here"

# Start server with JWT authentication
vt-cli mcp http --api-key your_api_key --jwt --jwt-secret "$JWT_SECRET"

# Or using environment variable for secret
JWT_SECRET="your-secret" vt-cli mcp http --api-key your_api_key --jwt
```

### OAuth 2.1 Authentication

Requires the `cli-mcp-oauth` feature:

```bash
# Set OAuth credentials
export OAUTH_CLIENT_ID="your_oauth_client_id"
export OAUTH_CLIENT_SECRET="your_oauth_client_secret"

# Start server with OAuth authentication
vt-cli mcp http --api-key your_api_key --oauth \
  --oauth-client-id "$OAUTH_CLIENT_ID" \
  --oauth-client-secret "$OAUTH_CLIENT_SECRET"
```

## Environment Variables

The CLI respects these environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | **Required** VirusTotal API key | - |
| `VIRUSTOTAL_API_TIER` | API tier: `Public` or `Premium` | `Public` |
| `JWT_SECRET` | JWT signing secret (HTTP + JWT mode) | - |
| `OAUTH_CLIENT_ID` | OAuth client ID (HTTP + OAuth mode) | - |
| `OAUTH_CLIENT_SECRET` | OAuth client secret (HTTP + OAuth mode) | - |

## Common Use Cases

### 1. Local Development with MCP Inspector

Perfect for testing and development:

```bash
# Start server
VIRUSTOTAL_API_KEY=your_key vt-cli mcp stdio

# In another terminal, connect with inspector
npx @modelcontextprotocol/inspector vt-cli mcp stdio
```

### 2. Remote Access for Team

Set up a shared HTTP server:

```bash
# Start on all interfaces with authentication
vt-cli mcp http \
  --api-key your_key \
  --addr 0.0.0.0:8080 \
  --jwt --jwt-secret "team-shared-secret"
```

### 3. Docker Deployment

```dockerfile
# Dockerfile
FROM rust:1.85 as builder
COPY . .
RUN cargo install virustotal-rs --features cli-mcp-jwt

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/vt-cli /usr/local/bin/
EXPOSE 3000
CMD ["vt-cli", "mcp", "http", "--addr", "0.0.0.0:3000"]
```

```bash
# Build and run
docker build -t vt-mcp-cli .
docker run -e VIRUSTOTAL_API_KEY=your_key -p 3000:3000 vt-mcp-cli
```

### 4. Integration with AI Applications

Configure the MCP client in your AI application:

```json
{
  "transport": {
    "type": "stdio",
    "command": "vt-cli",
    "args": ["mcp", "stdio"],
    "env": {
      "VIRUSTOTAL_API_KEY": "your_key"
    }
  }
}
```

## Troubleshooting

### Common Issues

#### "MCP feature not enabled"

```bash
error: MCP feature not enabled. Rebuild with --features mcp
```

**Solution**: Install with the correct features:
```bash
cargo install virustotal-rs --features cli-mcp
```

#### "API key required"

```bash
error: API key required. Use --api-key or set VIRUSTOTAL_API_KEY environment variable
```

**Solution**: Provide API key:
```bash
export VIRUSTOTAL_API_KEY=your_key
vt-cli mcp stdio
```

#### "Invalid address"

```bash
error: Invalid address '127.0.0.1:abc': invalid port number
```

**Solution**: Use valid IP:port format:
```bash
vt-cli mcp http --addr 127.0.0.1:3000
```

#### "JWT secret required"

```bash
error: JWT secret required when --jwt is enabled
```

**Solution**: Provide JWT secret:
```bash
vt-cli mcp http --jwt --jwt-secret "your-secret"
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
vt-cli --verbose mcp stdio --api-key your_key
```

### Port Binding Issues

If the default port is in use:

```bash
# Check what's using the port
lsof -i :3000

# Use a different port
vt-cli mcp http --addr 127.0.0.1:8080
```

## Integration Examples

### Claude Desktop Configuration

Complete configuration for Claude Desktop:

```json
{
  "mcpServers": {
    "virustotal": {
      "command": "vt-cli",
      "args": [
        "mcp", 
        "stdio",
        "--tier", "premium"
      ],
      "env": {
        "VIRUSTOTAL_API_KEY": "your_api_key_here"
      }
    }
  }
}
```

### SystemD Service

Create a systemd service file (`/etc/systemd/system/vt-mcp.service`):

```ini
[Unit]
Description=VirusTotal MCP Server
After=network.target

[Service]
Type=simple
User=vt-mcp
Environment=VIRUSTOTAL_API_KEY=your_key_here
Environment=VIRUSTOTAL_API_TIER=premium
ExecStart=/usr/local/bin/vt-cli mcp http --addr 127.0.0.1:3000
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start the service
sudo systemctl enable vt-mcp
sudo systemctl start vt-mcp
sudo systemctl status vt-mcp
```

### Docker Compose

```yaml
version: '3.8'

services:
  vt-mcp-server:
    build: .
    ports:
      - "3000:3000"
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
      - VIRUSTOTAL_API_TIER=premium
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vt-mcp-server
spec:
  replicas: 2
  selector:
    matchLabels:
      app: vt-mcp-server
  template:
    metadata:
      labels:
        app: vt-mcp-server
    spec:
      containers:
      - name: vt-mcp-server
        image: your-registry/vt-mcp-cli:latest
        ports:
        - containerPort: 3000
        env:
        - name: VIRUSTOTAL_API_KEY
          valueFrom:
            secretKeyRef:
              name: vt-secrets
              key: api-key
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: vt-mcp-service
spec:
  selector:
    app: vt-mcp-server
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3000
  type: ClusterIP
```

This guide provides comprehensive coverage of the integrated MCP CLI functionality. For additional support, please check the [main documentation](README.md) or open an issue on GitHub.