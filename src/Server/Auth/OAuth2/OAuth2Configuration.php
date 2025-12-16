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
 * Configuration for OAuth2 authentication in MCP servers.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class OAuth2Configuration
{
    /**
     * @param string[] $requiredScopes Scopes required for MCP access
     * @param string[] $publicPaths Paths that don't require authentication
     * @param string|null $realm OAuth2 realm for WWW-Authenticate header
     */
    public function __construct(
        public readonly OAuth2ProviderInterface $provider,
        public readonly array $requiredScopes = [],
        public readonly array $publicPaths = ['/.well-known/oauth-authorization-server'],
        public readonly bool $metadataEndpointEnabled = true,
        public readonly ?string $realm = null,
    ) {
    }

    /**
     * Check if a path requires authentication.
     */
    public function requiresAuthentication(string $path): bool
    {
        foreach ($this->publicPaths as $publicPath) {
            if ($path === $publicPath || str_starts_with($path, $publicPath.'/')) {
                return false;
            }
        }

        return true;
    }
}

