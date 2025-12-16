<?php

/**
 * OAuth2 Demo - MCP Server with OAuth2 Authentication.
 *
 * This example demonstrates how to create an MCP server that requires
 * OAuth2 authentication. It integrates with an external OAuth2 provider
 * (or the included mock server for testing).
 *
 * Features demonstrated:
 * - OAuth2 Bearer token validation
 * - Token introspection
 * - Access to authenticated user info in tools
 * - OAuth2 metadata endpoint
 *
 * Testing with Docker:
 *   docker-compose up
 *   # Visit http://localhost:8080
 *
 * Testing with MCP Inspector:
 *   npx @modelcontextprotocol/inspector http://localhost:8080 --header "Authorization: Bearer <token>"
 */

declare(strict_types=1);

require_once dirname(__DIR__).'/bootstrap.php';

use Http\Discovery\Psr17Factory;
use Http\Discovery\Psr18Client;
use Laminas\HttpHandlerRunner\Emitter\SapiEmitter;
use Mcp\Server;
use Mcp\Server\Auth\OAuth2\IntrospectionProvider;
use Mcp\Server\Auth\OAuth2\OAuth2Configuration;
use Mcp\Server\Session\FileSessionStore;
use Mcp\Server\Transport\OAuth2HttpTransport;

// Configuration from environment variables
// Note: Some URLs need to be different for browser (external) vs server-to-server (internal) communication
$oauth2Config = [
    'client_id' => getenv('OAUTH2_CLIENT_ID') ?: 'mcp-demo-client',
    'client_secret' => getenv('OAUTH2_CLIENT_SECRET') ?: 'mcp-demo-secret',
    // External URLs (for browser redirects and metadata)
    'issuer' => getenv('OAUTH2_ISSUER') ?: 'http://localhost:9000',
    'auth_url' => getenv('OAUTH2_AUTH_URL') ?: 'http://localhost:9000/authorize',
    'register_url' => getenv('OAUTH2_REGISTER_URL') ?: 'http://localhost:9000/register',
    // Internal URLs (for server-to-server communication)
    'token_url' => getenv('OAUTH2_TOKEN_URL') ?: 'http://localhost:9000/token',
    'introspect_url' => getenv('OAUTH2_INTROSPECT_URL') ?: 'http://localhost:9000/introspect',
];

// Handle non-MCP routes (OAuth callback, home page)
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', \PHP_URL_PATH);

if ('/' === $path && 'GET' === $_SERVER['REQUEST_METHOD']) {
    handleHomePage($oauth2Config);
    exit;
}

if ('/callback' === $path) {
    handleOAuthCallback($oauth2Config);
    exit;
}

if ('/start-auth' === $path) {
    startOAuthFlow($oauth2Config);
    exit;
}

// For MCP endpoints, use the OAuth2-enabled server
runMcpServer($oauth2Config);

// ============================================================================
// Route Handlers
// ============================================================================

function runMcpServer(array $oauth2Config): void
{
    $psr17Factory = new Psr17Factory();
    $httpClient = new Psr18Client();

    // External URLs for browser-facing metadata (may differ from internal URLs in Docker)
    $externalTokenUrl = getenv('OAUTH2_EXTERNAL_TOKEN_URL') ?: null;
    $externalIntrospectUrl = getenv('OAUTH2_EXTERNAL_INTROSPECT_URL') ?: null;

    // Create OAuth2 provider using token introspection
    $provider = new IntrospectionProvider(
        clientId: $oauth2Config['client_id'],
        clientSecret: $oauth2Config['client_secret'],
        authorizationUrl: $oauth2Config['auth_url'],
        tokenUrl: $oauth2Config['token_url'],
        introspectionUrl: $oauth2Config['introspect_url'],
        httpClient: $httpClient,
        requestFactory: $psr17Factory,
        streamFactory: $psr17Factory,
        requiredScopes: [], // No specific scopes required
        resourceServer: 'mcp-demo',
        issuer: $oauth2Config['issuer'],
        registrationUrl: $oauth2Config['register_url'],
        externalTokenUrl: $externalTokenUrl,
        externalIntrospectionUrl: $externalIntrospectUrl,
    );

    // Create OAuth2 configuration
    $oauth2 = new OAuth2Configuration(
        provider: $provider,
        requiredScopes: [],
        publicPaths: [
            '/.well-known/oauth-authorization-server',
            '/callback',
            '/start-auth',
        ],
        metadataEndpointEnabled: true,
        realm: 'MCP Demo Server',
    );

    // Build the MCP server with OAuth2 tools
    $server = Server::builder()
        ->setServerInfo('OAuth2 Demo Server', '1.0.0', 'MCP Server with OAuth2 authentication')
        ->setSession(new FileSessionStore(__DIR__.'/sessions'))
        ->setDiscovery(__DIR__, ['.'])
        ->setLogger(logger())
        ->build();

    // Create OAuth2-enabled HTTP transport
    $request = $psr17Factory->createServerRequestFromGlobals();
    $transport = new OAuth2HttpTransport(
        request: $request,
        oauth2Config: $oauth2,
        responseFactory: $psr17Factory,
        streamFactory: $psr17Factory,
        logger: logger(),
    );

    // Run the server and emit response
    $response = $server->run($transport);
    (new SapiEmitter())->emit($response);
}

function handleHomePage(array $oauth2Config): void
{
    $authUrl = $oauth2Config['auth_url'];
    echo <<<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCP OAuth2 Demo</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'SF Mono', 'Fira Code', monospace;
            min-height: 100vh;
            background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            color: #e0e0e0;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .container {
            max-width: 800px;
            padding: 40px;
            text-align: center;
        }
        h1 {
            font-size: 3rem;
            background: linear-gradient(135deg, #00d4aa, #7b68ee, #ff6b6b);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 20px;
        }
        .subtitle {
            color: #888;
            font-size: 1.2rem;
            margin-bottom: 40px;
        }
        .card {
            background: rgba(26, 26, 46, 0.8);
            border: 1px solid rgba(0, 212, 170, 0.2);
            border-radius: 16px;
            padding: 30px;
            margin-bottom: 30px;
            text-align: left;
        }
        .card h2 {
            color: #00d4aa;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .btn {
            display: inline-block;
            padding: 16px 32px;
            background: linear-gradient(135deg, #00d4aa 0%, #00a885 100%);
            color: #000;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 700;
            font-size: 1.1rem;
            transition: transform 0.2s, box-shadow 0.2s;
            margin: 10px;
        }
        .btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(0, 212, 170, 0.4);
        }
        .btn-secondary {
            background: #333;
            color: #ccc;
        }
        .btn-secondary:hover {
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.4);
        }
        code {
            background: #0a0a0f;
            padding: 4px 10px;
            border-radius: 4px;
            color: #ffd700;
            font-size: 0.9rem;
        }
        .endpoint {
            display: flex;
            align-items: center;
            padding: 12px;
            background: #0a0a0f;
            border-radius: 8px;
            margin: 8px 0;
        }
        .method {
            background: #00d4aa;
            color: #000;
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            margin-right: 15px;
            font-size: 0.8rem;
        }
        .method.post { background: #ff6b6b; color: #fff; }
        .token-display {
            background: #0a0a0f;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
            word-break: break-all;
            font-size: 0.85rem;
            color: #00d4aa;
            max-height: 150px;
            overflow-y: auto;
        }
        .actions {
            margin-top: 30px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 MCP OAuth2 Demo</h1>
        <p class="subtitle">Model Context Protocol Server with OAuth2 Authentication</p>
        
        <div class="card">
            <h2>📡 Available Endpoints</h2>
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/</code> - MCP endpoint (requires Bearer token)
            </div>
            <div class="endpoint">
                <span class="method">GET</span>
                <code>/.well-known/oauth-authorization-server</code> - OAuth2 metadata
            </div>
            <div class="endpoint">
                <span class="method">GET</span>
                <code>/callback</code> - OAuth2 callback handler
            </div>
        </div>
        
        <div class="card">
            <h2>🧪 Test the Authentication Flow</h2>
            <p style="color: #888; margin-bottom: 20px;">
                Click the button below to start the OAuth2 authorization flow. 
                After signing in, you'll receive an access token.
            </p>
            
            <div id="token-section" style="display: none;">
                <p style="color: #00d4aa; margin-bottom: 10px;">✓ Access Token:</p>
                <div class="token-display" id="token-display"></div>
                <button onclick="copyToken()" class="btn btn-secondary" style="cursor: pointer; border: none;">
                    📋 Copy Token
                </button>
            </div>
        </div>
        
        <div class="actions">
            <a href="/start-auth" class="btn">🚀 Start OAuth2 Flow</a>
            <a href="/.well-known/oauth-authorization-server" class="btn btn-secondary">📋 View Metadata</a>
        </div>
        
        <div class="card" style="margin-top: 30px;">
            <h2>🔌 Test with MCP Inspector</h2>
            <p style="color: #888;">Once you have a token, test with:</p>
            <div class="token-display" style="color: #ccc;">
                npx @modelcontextprotocol/inspector http://localhost:8080 --header "Authorization: Bearer YOUR_TOKEN"
            </div>
        </div>
    </div>
    
    <script>
        // Check for token in URL hash
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const token = params.get('access_token');
        
        if (token) {
            document.getElementById('token-section').style.display = 'block';
            document.getElementById('token-display').textContent = token;
            window.location.hash = '';
        }
        
        // Also check query string (from callback)
        const urlParams = new URLSearchParams(window.location.search);
        const queryToken = urlParams.get('access_token');
        if (queryToken) {
            document.getElementById('token-section').style.display = 'block';
            document.getElementById('token-display').textContent = queryToken;
            history.replaceState({}, '', '/');
        }
        
        function copyToken() {
            const token = document.getElementById('token-display').textContent;
            navigator.clipboard.writeText(token).then(() => {
                alert('Token copied to clipboard!');
            });
        }
    </script>
</body>
</html>
HTML;
}

function startOAuthFlow(array $oauth2Config): void
{
    // Generate PKCE challenge
    $codeVerifier = bin2hex(random_bytes(32));
    $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');

    // Store verifier in session/cookie for callback
    setcookie('oauth2_code_verifier', $codeVerifier, time() + 600, '/', '', false, true);

    // Generate state for CSRF protection
    $state = bin2hex(random_bytes(16));
    setcookie('oauth2_state', $state, time() + 600, '/', '', false, true);

    // Build authorization URL
    $params = http_build_query([
        'client_id' => $oauth2Config['client_id'],
        'redirect_uri' => 'http://localhost:8080/callback',
        'response_type' => 'code',
        'scope' => 'openid profile mcp:read mcp:write',
        'state' => $state,
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => 'S256',
    ]);

    $authUrl = $oauth2Config['auth_url'].'?'.$params;
    header('Location: '.$authUrl);
    exit;
}

function handleOAuthCallback(array $oauth2Config): void
{
    $code = $_GET['code'] ?? null;
    $state = $_GET['state'] ?? null;
    $error = $_GET['error'] ?? null;

    if ($error) {
        $errorDesc = $_GET['error_description'] ?? 'Unknown error';
        echo "<h1>OAuth Error</h1><p>{$error}: {$errorDesc}</p><a href='/'>Back</a>";

        return;
    }

    if (!$code) {
        echo '<h1>Error</h1><p>No authorization code received</p><a href="/">Back</a>';

        return;
    }

    // Verify state
    $storedState = $_COOKIE['oauth2_state'] ?? null;
    if ($state !== $storedState) {
        echo '<h1>Error</h1><p>Invalid state parameter (CSRF protection)</p><a href="/">Back</a>';

        return;
    }

    // Get code verifier from cookie
    $codeVerifier = $_COOKIE['oauth2_code_verifier'] ?? null;

    // Exchange code for token
    $tokenData = [
        'grant_type' => 'authorization_code',
        'code' => $code,
        'redirect_uri' => 'http://localhost:8080/callback',
        'client_id' => $oauth2Config['client_id'],
        'client_secret' => $oauth2Config['client_secret'],
    ];

    if ($codeVerifier) {
        $tokenData['code_verifier'] = $codeVerifier;
    }

    $ch = curl_init($oauth2Config['token_url']);
    curl_setopt_array($ch, [
        \CURLOPT_POST => true,
        \CURLOPT_POSTFIELDS => http_build_query($tokenData),
        \CURLOPT_RETURNTRANSFER => true,
        \CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, \CURLINFO_HTTP_CODE);
    curl_close($ch);

    if (200 !== $httpCode) {
        echo "<h1>Token Exchange Failed</h1><p>HTTP {$httpCode}: {$response}</p><a href='/'>Back</a>";

        return;
    }

    $tokens = json_decode($response, true);
    $accessToken = $tokens['access_token'] ?? null;

    if (!$accessToken) {
        echo '<h1>Error</h1><p>No access token in response</p><a href="/">Back</a>';

        return;
    }

    // Clear cookies
    setcookie('oauth2_code_verifier', '', time() - 3600, '/');
    setcookie('oauth2_state', '', time() - 3600, '/');

    // Redirect back to home with token
    header('Location: /?access_token='.urlencode($accessToken));
    exit;
}
