<?php

/**
 * Mock OAuth2 Authorization Server for Testing.
 *
 * This is a simple OAuth2 server that implements:
 * - Authorization endpoint with PKCE support
 * - Token endpoint
 * - Token introspection endpoint
 * - Dynamic Client Registration (RFC 7591)
 *
 * NOT FOR PRODUCTION USE - This is for development and testing only.
 *
 * Endpoints:
 *   GET  /authorize     - Authorization endpoint (redirects user)
 *   POST /token         - Token endpoint
 *   POST /introspect    - Token introspection (RFC 7662)
 *   POST /register      - Dynamic Client Registration (RFC 7591)
 *   GET  /.well-known/oauth-authorization-server - Metadata
 */

// Configuration from environment or defaults
$config = [
    'client_id' => getenv('OAUTH2_CLIENT_ID') ?: 'mcp-demo-client',
    'client_secret' => getenv('OAUTH2_CLIENT_SECRET') ?: 'mcp-demo-secret',
    'redirect_uri' => getenv('OAUTH2_REDIRECT_URI') ?: 'http://localhost:8080/callback',
    'issuer' => 'http://localhost:9000',
    'token_lifetime' => 3600,
];

// Simple in-memory storage for authorization codes and tokens
$storage = [];
$storageFile = '/tmp/oauth2-storage.json';

function loadStorage(): array
{
    global $storageFile;
    if (file_exists($storageFile)) {
        return json_decode(file_get_contents($storageFile), true) ?: [];
    }

    return [];
}

function saveStorage(array $data): void
{
    global $storageFile;
    file_put_contents($storageFile, json_encode($data));
}

// Parse the request
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], \PHP_URL_PATH);

// Set CORS headers for all responses
setCorsHeaders();

// Handle OPTIONS preflight requests
if ('OPTIONS' === $method) {
    http_response_code(204);
    exit;
}

// Route the request
try {
    match (true) {
        'GET' === $method && '/.well-known/oauth-authorization-server' === $path => handleMetadata(),
        'GET' === $method && '/authorize' === $path => handleAuthorize(),
        'POST' === $method && '/authorize' === $path => handleAuthorizeSubmit(),
        'POST' === $method && '/token' === $path => handleToken(),
        'POST' === $method && '/introspect' === $path => handleIntrospect(),
        'POST' === $method && '/register' === $path => handleRegister(),
        'GET' === $method && '/' === $path => handleHomePage(),
        default => handleNotFound(),
    };
} catch (\Throwable $e) {
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'server_error', 'error_description' => $e->getMessage()]);
}

/**
 * Set CORS headers to allow cross-origin requests from MCP clients.
 */
function setCorsHeaders(): void
{
    // Allow requests from any origin (for development)
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
    header('Access-Control-Max-Age: 86400');
}

// ============================================================================
// Request Handlers
// ============================================================================

function handleMetadata(): void
{
    global $config;
    header('Content-Type: application/json');
    echo json_encode([
        'issuer' => $config['issuer'],
        'authorization_endpoint' => $config['issuer'].'/authorize',
        'token_endpoint' => $config['issuer'].'/token',
        'introspection_endpoint' => $config['issuer'].'/introspect',
        'registration_endpoint' => $config['issuer'].'/register',
        'response_types_supported' => ['code'],
        'grant_types_supported' => ['authorization_code', 'refresh_token'],
        'code_challenge_methods_supported' => ['S256', 'plain'],
        'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
        'scopes_supported' => ['openid', 'profile', 'mcp:read', 'mcp:write'],
    ], \JSON_PRETTY_PRINT);
}

function handleHomePage(): void
{
    header('Content-Type: text/html');
    echo <<<'HTML'
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Mock OAuth2 Server</title>
        <style>
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background: #0a0a0f;
                color: #e0e0e0;
            }
            h1 { color: #00d4aa; }
            code {
                background: #1a1a2e;
                padding: 2px 8px;
                border-radius: 4px;
                color: #ffd700;
            }
            .endpoint {
                background: #1a1a2e;
                padding: 15px;
                margin: 10px 0;
                border-radius: 8px;
                border-left: 4px solid #00d4aa;
            }
            .method { color: #ff6b6b; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>🔐 Mock OAuth2 Authorization Server</h1>
        <p>This is a development OAuth2 server for testing the PHP MCP SDK.</p>
        
        <h2>Endpoints</h2>
        <div class="endpoint">
            <span class="method">GET</span> <code>/authorize</code> - Authorization endpoint
        </div>
        <div class="endpoint">
            <span class="method">POST</span> <code>/token</code> - Token endpoint
        </div>
        <div class="endpoint">
            <span class="method">POST</span> <code>/introspect</code> - Token introspection
        </div>
        <div class="endpoint">
            <span class="method">GET</span> <code>/.well-known/oauth-authorization-server</code> - Metadata
        </div>
        
        <h2>Test Credentials</h2>
        <p>Client ID: <code>mcp-demo-client</code></p>
        <p>Client Secret: <code>mcp-demo-secret</code></p>
        <p>Test User: <code>demo</code> / <code>demo</code></p>
    </body>
    </html>
    HTML;
}

function handleAuthorize(): void
{
    global $config;

    // Validate required parameters
    $clientId = $_GET['client_id'] ?? '';
    $redirectUri = $_GET['redirect_uri'] ?? '';
    $responseType = $_GET['response_type'] ?? '';
    $scope = $_GET['scope'] ?? 'openid';
    $state = $_GET['state'] ?? '';
    $codeChallenge = $_GET['code_challenge'] ?? '';
    $codeChallengeMethod = $_GET['code_challenge_method'] ?? 'plain';

    // Check if client is the default client or a dynamically registered client
    $validClient = false;
    $clientName = 'MCP Demo Client';

    if ($clientId === $config['client_id']) {
        $validClient = true;
    } else {
        // Check dynamically registered clients
        $storage = loadStorage();
        if (isset($storage['clients'][$clientId])) {
            $client = $storage['clients'][$clientId];
            $validClient = true;
            $clientName = $client['client_name'] ?? 'Dynamic Client';

            // Validate redirect URI for dynamic clients
            if (!empty($redirectUri) && !in_array($redirectUri, $client['redirect_uris'] ?? [], true)) {
                errorResponse('invalid_redirect_uri', 'Redirect URI not registered for this client');

                return;
            }
        }
    }

    if (!$validClient) {
        errorResponse('invalid_client', 'Unknown client_id');

        return;
    }

    if ('code' !== $responseType) {
        redirectWithError($redirectUri, 'unsupported_response_type', 'Only code response type is supported', $state);

        return;
    }

    // Show login form
    header('Content-Type: text/html');
    echo <<<HTML
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sign In - Mock OAuth2</title>
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                background: linear-gradient(135deg, #0a0a0f 0%, #1a1a2e 50%, #16213e 100%);
            }
            .login-container {
                background: rgba(26, 26, 46, 0.95);
                padding: 40px;
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                width: 100%;
                max-width: 400px;
                border: 1px solid rgba(0, 212, 170, 0.2);
            }
            h1 {
                color: #00d4aa;
                text-align: center;
                margin-bottom: 10px;
                font-size: 28px;
            }
            .subtitle {
                color: #888;
                text-align: center;
                margin-bottom: 30px;
                font-size: 14px;
            }
            .client-info {
                background: rgba(0, 212, 170, 0.1);
                padding: 12px;
                border-radius: 8px;
                margin-bottom: 25px;
                text-align: center;
                color: #00d4aa;
                font-size: 14px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                color: #ccc;
                margin-bottom: 8px;
                font-size: 14px;
            }
            input[type="text"], input[type="password"] {
                width: 100%;
                padding: 14px 16px;
                background: #0a0a0f;
                border: 2px solid #333;
                border-radius: 8px;
                color: #fff;
                font-size: 16px;
                transition: border-color 0.3s;
            }
            input[type="text"]:focus, input[type="password"]:focus {
                outline: none;
                border-color: #00d4aa;
            }
            .scopes {
                background: #0a0a0f;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 25px;
            }
            .scopes h3 {
                color: #888;
                font-size: 12px;
                text-transform: uppercase;
                margin-bottom: 10px;
            }
            .scope-item {
                display: flex;
                align-items: center;
                padding: 8px 0;
                color: #ccc;
            }
            .scope-item::before {
                content: '✓';
                color: #00d4aa;
                margin-right: 10px;
            }
            .buttons {
                display: flex;
                gap: 12px;
            }
            button {
                flex: 1;
                padding: 14px 20px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
            }
            .btn-primary {
                background: linear-gradient(135deg, #00d4aa 0%, #00a885 100%);
                color: #000;
            }
            .btn-primary:hover {
                box-shadow: 0 8px 25px rgba(0, 212, 170, 0.4);
            }
            .btn-secondary {
                background: #333;
                color: #ccc;
            }
            .hint {
                text-align: center;
                margin-top: 20px;
                color: #666;
                font-size: 12px;
            }
        </style>
    </head>
    <body>
        <div class="login-container">
            <h1>🔐 Sign In</h1>
            <p class="subtitle">Mock OAuth2 Authorization Server</p>
            
            <div class="client-info">
                <strong>{$clientName}</strong> is requesting access
            </div>
            
            <form method="POST" action="/authorize">
                <input type="hidden" name="client_id" value="{$clientId}">
                <input type="hidden" name="redirect_uri" value="{$redirectUri}">
                <input type="hidden" name="scope" value="{$scope}">
                <input type="hidden" name="state" value="{$state}">
                <input type="hidden" name="code_challenge" value="{$codeChallenge}">
                <input type="hidden" name="code_challenge_method" value="{$codeChallengeMethod}">
                
                <div class="form-group">
                    <label for="username">Username</label>
                    <input type="text" id="username" name="username" placeholder="Enter username" required>
                </div>
                
                <div class="form-group">
                    <label for="password">Password</label>
                    <input type="password" id="password" name="password" placeholder="Enter password" required>
                </div>
                
                <div class="scopes">
                    <h3>Requested Permissions</h3>
                    {$scope}
                </div>
                
                <div class="buttons">
                    <button type="button" class="btn-secondary" onclick="window.close()">Cancel</button>
                    <button type="submit" class="btn-primary">Authorize</button>
                </div>
            </form>
            
            <p class="hint">Test credentials: demo / demo</p>
        </div>
    </body>
    </html>
    HTML;
}

function handleAuthorizeSubmit(): void
{
    global $config;

    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $clientId = $_POST['client_id'] ?? '';
    $redirectUri = $_POST['redirect_uri'] ?? '';
    $scope = $_POST['scope'] ?? 'openid';
    $state = $_POST['state'] ?? '';
    $codeChallenge = $_POST['code_challenge'] ?? '';
    $codeChallengeMethod = $_POST['code_challenge_method'] ?? 'plain';

    // Simple credential validation (demo/demo)
    if ('demo' !== $username || 'demo' !== $password) {
        http_response_code(401);
        header('Content-Type: text/html');
        echo '<html><body><h1>Invalid credentials</h1><p>Use demo/demo</p><a href="javascript:history.back()">Back</a></body></html>';

        return;
    }

    // Generate authorization code
    $code = bin2hex(random_bytes(32));

    // Store the code with metadata
    $storage = loadStorage();
    $storage['codes'][$code] = [
        'client_id' => $clientId,
        'redirect_uri' => $redirectUri,
        'scope' => $scope,
        'user_id' => $username,
        'code_challenge' => $codeChallenge,
        'code_challenge_method' => $codeChallengeMethod,
        'created_at' => time(),
        'expires_at' => time() + 600, // 10 minutes
    ];
    saveStorage($storage);

    // Redirect back to client with authorization code
    $redirectUrl = $redirectUri.'?'.http_build_query(array_filter([
        'code' => $code,
        'state' => $state,
    ]));

    header('Location: '.$redirectUrl);
    exit;
}

function handleToken(): void
{
    global $config;

    // Get client credentials (Basic auth or POST body)
    $clientId = null;
    $clientSecret = null;

    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (str_starts_with($authHeader, 'Basic ')) {
        $decoded = base64_decode(substr($authHeader, 6));
        [$clientId, $clientSecret] = explode(':', $decoded, 2);
    } else {
        $clientId = $_POST['client_id'] ?? '';
        $clientSecret = $_POST['client_secret'] ?? '';
    }

    // Validate client - check default client or dynamically registered clients
    $validClient = false;
    $clientAuthMethod = 'client_secret_basic';

    if ($clientId === $config['client_id'] && $clientSecret === $config['client_secret']) {
        $validClient = true;
    } else {
        // Check dynamically registered clients
        $storage = loadStorage();
        if (isset($storage['clients'][$clientId])) {
            $client = $storage['clients'][$clientId];
            $clientAuthMethod = $client['token_endpoint_auth_method'] ?? 'client_secret_basic';

            if ('none' === $clientAuthMethod) {
                // Public client - no secret required
                $validClient = true;
            } elseif (isset($client['client_secret']) && $client['client_secret'] === $clientSecret) {
                $validClient = true;
            }
        }
    }

    if (!$validClient) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_client', 'error_description' => 'Invalid client credentials']);

        return;
    }

    $grantType = $_POST['grant_type'] ?? '';

    if ('authorization_code' === $grantType) {
        handleAuthorizationCodeGrant($clientId);
    } elseif ('refresh_token' === $grantType) {
        handleRefreshTokenGrant();
    } else {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'unsupported_grant_type']);
    }
}

function handleAuthorizationCodeGrant(string $clientId = ''): void
{
    global $config;

    $code = $_POST['code'] ?? '';
    $redirectUri = $_POST['redirect_uri'] ?? '';
    $codeVerifier = $_POST['code_verifier'] ?? '';

    $storage = loadStorage();

    // Validate code
    if (!isset($storage['codes'][$code])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_grant', 'error_description' => 'Invalid authorization code']);

        return;
    }

    $codeData = $storage['codes'][$code];

    // Check expiration
    if (time() > $codeData['expires_at']) {
        unset($storage['codes'][$code]);
        saveStorage($storage);
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_grant', 'error_description' => 'Authorization code has expired']);

        return;
    }

    // Validate PKCE if present
    if (!empty($codeData['code_challenge'])) {
        if (empty($codeVerifier)) {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'invalid_grant', 'error_description' => 'PKCE code_verifier required']);

            return;
        }

        $expectedChallenge = 'S256' === $codeData['code_challenge_method']
            ? rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=')
            : $codeVerifier;

        if ($expectedChallenge !== $codeData['code_challenge']) {
            http_response_code(400);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'invalid_grant', 'error_description' => 'PKCE verification failed']);

            return;
        }
    }

    // Remove used code
    unset($storage['codes'][$code]);

    // Generate tokens
    $accessToken = bin2hex(random_bytes(32));
    $refreshToken = bin2hex(random_bytes(32));

    // Store tokens
    $storage['tokens'][$accessToken] = [
        'client_id' => $codeData['client_id'],
        'user_id' => $codeData['user_id'],
        'scope' => $codeData['scope'],
        'created_at' => time(),
        'expires_at' => time() + $config['token_lifetime'],
    ];

    $storage['refresh_tokens'][$refreshToken] = [
        'client_id' => $codeData['client_id'],
        'user_id' => $codeData['user_id'],
        'scope' => $codeData['scope'],
        'created_at' => time(),
        'expires_at' => time() + 86400 * 30, // 30 days
    ];

    saveStorage($storage);

    // Return token response
    header('Content-Type: application/json');
    echo json_encode([
        'access_token' => $accessToken,
        'token_type' => 'Bearer',
        'expires_in' => $config['token_lifetime'],
        'refresh_token' => $refreshToken,
        'scope' => $codeData['scope'],
    ]);
}

function handleRefreshTokenGrant(): void
{
    global $config;

    $refreshToken = $_POST['refresh_token'] ?? '';

    $storage = loadStorage();

    if (!isset($storage['refresh_tokens'][$refreshToken])) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_grant', 'error_description' => 'Invalid refresh token']);

        return;
    }

    $tokenData = $storage['refresh_tokens'][$refreshToken];

    if (time() > $tokenData['expires_at']) {
        unset($storage['refresh_tokens'][$refreshToken]);
        saveStorage($storage);
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_grant', 'error_description' => 'Refresh token has expired']);

        return;
    }

    // Generate new access token
    $accessToken = bin2hex(random_bytes(32));

    $storage['tokens'][$accessToken] = [
        'client_id' => $tokenData['client_id'],
        'user_id' => $tokenData['user_id'],
        'scope' => $tokenData['scope'],
        'created_at' => time(),
        'expires_at' => time() + $config['token_lifetime'],
    ];

    saveStorage($storage);

    header('Content-Type: application/json');
    echo json_encode([
        'access_token' => $accessToken,
        'token_type' => 'Bearer',
        'expires_in' => $config['token_lifetime'],
        'scope' => $tokenData['scope'],
    ]);
}

function handleIntrospect(): void
{
    global $config;

    // Validate client credentials
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!str_starts_with($authHeader, 'Basic ')) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_client']);

        return;
    }

    $decoded = base64_decode(substr($authHeader, 6));
    [$clientId, $clientSecret] = explode(':', $decoded, 2);

    // Check default client or dynamically registered clients
    $validClient = false;
    if ($clientId === $config['client_id'] && $clientSecret === $config['client_secret']) {
        $validClient = true;
    } else {
        // Check dynamically registered clients
        $storage = loadStorage();
        if (isset($storage['clients'][$clientId])) {
            $client = $storage['clients'][$clientId];
            if (isset($client['client_secret']) && $client['client_secret'] === $clientSecret) {
                $validClient = true;
            } elseif ('none' === ($client['token_endpoint_auth_method'] ?? '')) {
                $validClient = true;
            }
        }
    }

    if (!$validClient) {
        http_response_code(401);
        header('Content-Type: application/json');
        echo json_encode(['error' => 'invalid_client']);

        return;
    }

    $token = $_POST['token'] ?? '';
    $storage = loadStorage();

    // Check if token exists and is valid
    if (!isset($storage['tokens'][$token])) {
        header('Content-Type: application/json');
        echo json_encode(['active' => false]);

        return;
    }

    $tokenData = $storage['tokens'][$token];

    // Check expiration
    if (time() > $tokenData['expires_at']) {
        unset($storage['tokens'][$token]);
        saveStorage($storage);
        header('Content-Type: application/json');
        echo json_encode(['active' => false]);

        return;
    }

    // Return introspection response
    header('Content-Type: application/json');
    echo json_encode([
        'active' => true,
        'client_id' => $tokenData['client_id'],
        'sub' => $tokenData['user_id'],
        'scope' => $tokenData['scope'],
        'exp' => $tokenData['expires_at'],
        'iat' => $tokenData['created_at'],
        'token_type' => 'Bearer',
    ]);
}

/**
 * Handle Dynamic Client Registration (RFC 7591).
 *
 * This endpoint allows clients to register dynamically without
 * pre-configuration. Required for MCP clients.
 */
function handleRegister(): void
{
    global $config;

    // Get request body
    $body = file_get_contents('php://input');
    $request = json_decode($body, true);

    if (!$request) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'invalid_request',
            'error_description' => 'Invalid JSON body',
        ]);

        return;
    }

    // Generate client credentials
    $clientId = 'client_'.bin2hex(random_bytes(16));
    $clientSecret = bin2hex(random_bytes(32));

    // Get redirect URIs from request
    $redirectUris = $request['redirect_uris'] ?? [];
    if (empty($redirectUris)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'invalid_redirect_uri',
            'error_description' => 'redirect_uris is required',
        ]);

        return;
    }

    // Determine token endpoint auth method
    $tokenEndpointAuthMethod = $request['token_endpoint_auth_method'] ?? 'client_secret_basic';
    $validAuthMethods = ['client_secret_basic', 'client_secret_post', 'none'];
    if (!in_array($tokenEndpointAuthMethod, $validAuthMethods, true)) {
        http_response_code(400);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => 'invalid_client_metadata',
            'error_description' => 'Unsupported token_endpoint_auth_method',
        ]);

        return;
    }

    // Build client metadata
    $clientMetadata = [
        'client_id' => $clientId,
        'client_secret' => $clientSecret,
        'client_secret_expires_at' => 0, // Never expires
        'redirect_uris' => $redirectUris,
        'token_endpoint_auth_method' => $tokenEndpointAuthMethod,
        'grant_types' => $request['grant_types'] ?? ['authorization_code', 'refresh_token'],
        'response_types' => $request['response_types'] ?? ['code'],
        'client_name' => $request['client_name'] ?? 'Dynamic Client',
        'scope' => $request['scope'] ?? 'openid profile mcp:read mcp:write',
        'created_at' => time(),
    ];

    // If auth method is 'none', don't include client_secret
    if ('none' === $tokenEndpointAuthMethod) {
        unset($clientMetadata['client_secret']);
    }

    // Store the client
    $storage = loadStorage();
    $storage['clients'] = $storage['clients'] ?? [];
    $storage['clients'][$clientId] = $clientMetadata;
    saveStorage($storage);

    // Return client registration response (RFC 7591 Section 3.2.1)
    http_response_code(201);
    header('Content-Type: application/json');
    echo json_encode($clientMetadata, \JSON_PRETTY_PRINT | \JSON_UNESCAPED_SLASHES);
}

function handleNotFound(): void
{
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'not_found', 'error_description' => 'Endpoint not found']);
}

function errorResponse(string $error, string $description): void
{
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode(['error' => $error, 'error_description' => $description]);
}

function redirectWithError(string $redirectUri, string $error, string $description, string $state): void
{
    $url = $redirectUri.'?'.http_build_query(array_filter([
        'error' => $error,
        'error_description' => $description,
        'state' => $state,
    ]));
    header('Location: '.$url);
    exit;
}

