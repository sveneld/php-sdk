# OAuth2 Demo

This example demonstrates how to create an MCP server with OAuth2 authentication.

## Features

- Complete OAuth2 authorization code flow with PKCE
- Token introspection for validation
- OAuth2 metadata endpoint
- Protected MCP tools
- Mock OAuth2 server for testing

## Quick Start

1. Start the mock OAuth2 server:

```bash
php -S localhost:9000 mock-oauth2-server.php
```

2. In another terminal, start the MCP server:

```bash
php -S localhost:8080 server.php
```

3. Visit http://localhost:8080 in your browser

## Testing the Flow

1. Open http://localhost:8080
2. Click "Start OAuth2 Flow"
3. Sign in with `demo` / `demo`
4. Copy the access token
5. Test with MCP Inspector:

```bash
npx @modelcontextprotocol/inspector \
    http://localhost:8080 \
    --header "Authorization: Bearer YOUR_TOKEN"
```

## Available Tools

- `get_current_user` - Get information about the authenticated user
- `protected_action` - Perform a protected action
- `list_my_scopes` - List available OAuth2 scopes
- `authenticated_echo` - Echo a message (requires auth)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH2_CLIENT_ID` | `mcp-demo-client` | OAuth2 client ID |
| `OAUTH2_CLIENT_SECRET` | `mcp-demo-secret` | OAuth2 client secret |
| `OAUTH2_ISSUER` | `http://localhost:9000` | OAuth2 issuer URL |
| `OAUTH2_AUTH_URL` | `http://localhost:9000/authorize` | Authorization endpoint |
| `OAUTH2_TOKEN_URL` | `http://localhost:9000/token` | Token endpoint |
| `OAUTH2_INTROSPECT_URL` | `http://localhost:9000/introspect` | Introspection endpoint |

## Mock OAuth2 Server

The mock server (`mock-oauth2-server.php`) provides:

- `GET /.well-known/oauth-authorization-server` - OAuth2 metadata
- `GET /authorize` - Authorization endpoint (login form)
- `POST /authorize` - Process login
- `POST /token` - Token endpoint
- `POST /introspect` - Token introspection

Test credentials: `demo` / `demo`

