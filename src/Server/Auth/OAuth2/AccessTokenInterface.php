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
 * Interface representing a validated OAuth2 access token.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
interface AccessTokenInterface
{
    /**
     * Get the raw token string.
     */
    public function getToken(): string;

    /**
     * Get the unique identifier for the token subject (user/client).
     */
    public function getSubject(): ?string;

    /**
     * Get the client ID associated with this token.
     */
    public function getClientId(): ?string;

    /**
     * Get the scopes granted to this token.
     *
     * @return string[]
     */
    public function getScopes(): array;

    /**
     * Check if the token has a specific scope.
     */
    public function hasScope(string $scope): bool;

    /**
     * Get the token expiration time.
     */
    public function getExpiresAt(): ?\DateTimeImmutable;

    /**
     * Check if the token has expired.
     */
    public function isExpired(): bool;

    /**
     * Get any additional claims/attributes from the token.
     *
     * @return array<string, mixed>
     */
    public function getClaims(): array;

    /**
     * Get a specific claim value.
     */
    public function getClaim(string $name, mixed $default = null): mixed;
}

