<?php

/*
 * This file is part of the official PHP MCP SDK.
 *
 * A collaboration between Symfony and the PHP Foundation.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mcp\Server\Transport;

use Http\Discovery\Psr17FactoryDiscovery;
use Mcp\Server\Auth\OAuth2\AccessTokenInterface;
use Mcp\Server\Auth\OAuth2\OAuth2Configuration;
use Mcp\Server\Auth\OAuth2\OAuth2Exception;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * HTTP Transport with OAuth2 authentication support.
 *
 * This transport extends StreamableHttpTransport to add:
 * - Bearer token validation
 * - OAuth2 metadata endpoint (/.well-known/oauth-authorization-server)
 * - Authentication error responses with WWW-Authenticate headers
 *
 * @extends BaseTransport<ResponseInterface>
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class OAuth2HttpTransport extends StreamableHttpTransport
{
    private ?AccessTokenInterface $validatedToken = null;
    private ServerRequestInterface $request;
    private ResponseFactoryInterface $responseFactory;
    private StreamFactoryInterface $streamFactory;

    /**
     * @param array<string, string> $corsHeaders
     */
    public function __construct(
        ServerRequestInterface $request,
        private readonly OAuth2Configuration $oauth2Config,
        ?ResponseFactoryInterface $responseFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        array $corsHeaders = [],
        ?LoggerInterface $logger = null,
    ) {
        $this->request = $request;
        $this->responseFactory = $responseFactory ?? Psr17FactoryDiscovery::findResponseFactory();
        $this->streamFactory = $streamFactory ?? Psr17FactoryDiscovery::findStreamFactory();

        parent::__construct($request, $this->responseFactory, $this->streamFactory, $corsHeaders, $logger);
    }

    public function listen(): ResponseInterface
    {
        $path = $this->getRequestPath();

        // Handle OAuth2 metadata endpoint
        if ($this->oauth2Config->metadataEndpointEnabled && $this->isMetadataRequest($path)) {
            return $this->handleMetadataRequest();
        }

        // Check if authentication is required for this path
        if ($this->oauth2Config->requiresAuthentication($path)) {
            try {
                $this->authenticate();
            } catch (OAuth2Exception $e) {
                return $this->createAuthErrorResponse($e);
            }
        }

        return parent::listen();
    }

    /**
     * Get the validated access token (available after successful authentication).
     */
    public function getValidatedToken(): ?AccessTokenInterface
    {
        return $this->validatedToken;
    }

    /**
     * Authenticate the request using the OAuth2 provider.
     *
     * @throws OAuth2Exception
     */
    private function authenticate(): void
    {
        $token = $this->extractBearerToken();

        if (null === $token) {
            throw OAuth2Exception::missingToken();
        }

        $this->validatedToken = $this->oauth2Config->provider->validateToken($token);

        // Check required scopes from configuration
        foreach ($this->oauth2Config->requiredScopes as $scope) {
            if (!$this->validatedToken->hasScope($scope)) {
                throw OAuth2Exception::insufficientScope($this->oauth2Config->requiredScopes);
            }
        }

        $this->logger->info('OAuth2 authentication successful', [
            'subject' => $this->validatedToken->getSubject(),
            'client_id' => $this->validatedToken->getClientId(),
            'scopes' => $this->validatedToken->getScopes(),
        ]);
    }

    /**
     * Extract Bearer token from Authorization header.
     */
    private function extractBearerToken(): ?string
    {
        $authHeader = $this->request->getHeaderLine('Authorization');

        if ('' === $authHeader) {
            return null;
        }

        if (!str_starts_with($authHeader, 'Bearer ')) {
            return null;
        }

        $token = substr($authHeader, 7);

        return '' === $token ? null : $token;
    }

    /**
     * Get the request path.
     */
    private function getRequestPath(): string
    {
        return $this->request->getUri()->getPath();
    }

    /**
     * Check if this is a metadata request.
     */
    private function isMetadataRequest(string $path): bool
    {
        return '/.well-known/oauth-authorization-server' === $path;
    }

    /**
     * Handle OAuth2 authorization server metadata request (RFC 8414).
     */
    private function handleMetadataRequest(): ResponseInterface
    {
        $metadata = $this->oauth2Config->provider->getMetadata();

        try {
            $body = json_encode($metadata, \JSON_THROW_ON_ERROR | \JSON_PRETTY_PRINT);
        } catch (\JsonException $e) {
            $this->logger->error('Failed to encode OAuth2 metadata', ['exception' => $e]);
            $body = '{}';
        }

        $response = $this->responseFactory->createResponse(200)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streamFactory->createStream($body));

        return $this->withCorsHeaders($response);
    }

    /**
     * Create an OAuth2 error response.
     */
    private function createAuthErrorResponse(OAuth2Exception $e): ResponseInterface
    {
        $this->logger->warning('OAuth2 authentication failed', [
            'error' => $e->getError(),
            'description' => $e->getErrorDescription(),
        ]);

        $body = json_encode([
            'error' => $e->getError(),
            'error_description' => $e->getErrorDescription(),
        ], \JSON_THROW_ON_ERROR);

        $response = $this->responseFactory->createResponse($e->getHttpStatusCode())
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('WWW-Authenticate', $e->getWwwAuthenticateHeader($this->oauth2Config->realm))
            ->withBody($this->streamFactory->createStream($body));

        return $this->withCorsHeaders($response);
    }
}

