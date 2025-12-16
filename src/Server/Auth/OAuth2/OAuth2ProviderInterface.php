<?php

/*
 * This file is part of the official PHP MCP SDK.
 *
 * A collaboration between Symfony and the PHP Foundation.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mcp\Server\Auth\OAuth2;

/**
 * Interface for OAuth2 token validation providers.
 *
 * Implementations can validate tokens via JWT verification, introspection endpoints,
 * or custom validation logic.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
interface OAuth2ProviderInterface
{
    /**
     * Validate an access token and return the token details.
     *
     * @param string $token The raw access token (without "Bearer " prefix)
     *
     * @return AccessTokenInterface The validated token with claims
     *
     * @throws OAuth2Exception If token validation fails
     */
    public function validateToken(string $token): AccessTokenInterface;

    /**
     * Get the OAuth2 authorization server metadata.
     *
     * Returns RFC 8414 compliant metadata for /.well-known/oauth-authorization-server
     *
     * @return array<string, mixed> Authorization server metadata
     */
    public function getMetadata(): array;

    /**
     * Get the authorization endpoint URL.
     *
     * This is used to redirect users for authentication.
     */
    public function getAuthorizationUrl(): string;

    /**
     * Get the token endpoint URL.
     */
    public function getTokenUrl(): string;

    /**
     * Get the required scopes for MCP operations.
     *
     * @return string[]
     */
    public function getRequiredScopes(): array;

    /**
     * Get the resource server identifier (audience).
     */
    public function getResourceServer(): ?string;
}

