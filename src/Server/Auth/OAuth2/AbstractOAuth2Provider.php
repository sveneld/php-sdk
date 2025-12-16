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
 * Abstract base class for OAuth2 providers.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
abstract class AbstractOAuth2Provider implements OAuth2ProviderInterface
{
    /**
     * @param string[] $requiredScopes
     */
    public function __construct(
        protected readonly string $clientId,
        protected readonly string $clientSecret,
        protected readonly string $authorizationUrl,
        protected readonly string $tokenUrl,
        protected readonly array $requiredScopes = [],
        protected readonly ?string $resourceServer = null,
        protected readonly ?string $issuer = null,
    ) {
    }

    public function getAuthorizationUrl(): string
    {
        return $this->authorizationUrl;
    }

    public function getTokenUrl(): string
    {
        return $this->tokenUrl;
    }

    public function getRequiredScopes(): array
    {
        return $this->requiredScopes;
    }

    public function getResourceServer(): ?string
    {
        return $this->resourceServer;
    }

    public function getMetadata(): array
    {
        return [
            'issuer' => $this->issuer ?? $this->authorizationUrl,
            'authorization_endpoint' => $this->authorizationUrl,
            'token_endpoint' => $this->tokenUrl,
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
        ];
    }

    /**
     * Validate that the token has the required scopes.
     *
     * @throws OAuth2Exception
     */
    protected function validateScopes(AccessTokenInterface $token): void
    {
        $requiredScopes = $this->getRequiredScopes();

        if (empty($requiredScopes)) {
            return;
        }

        foreach ($requiredScopes as $scope) {
            if (!$token->hasScope($scope)) {
                throw OAuth2Exception::insufficientScope($requiredScopes);
            }
        }
    }

    /**
     * Check if the token has expired.
     *
     * @throws OAuth2Exception
     */
    protected function validateExpiration(AccessTokenInterface $token): void
    {
        if ($token->isExpired()) {
            throw OAuth2Exception::expiredToken();
        }
    }
}

