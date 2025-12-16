<?php

/*
 * This file is part of the official PHP MCP SDK.
 *
 * A collaboration between Symfony and the PHP Foundation.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mcp\Server\Auth;

use Mcp\Server\Auth\OAuth2\AccessTokenInterface;

/**
 * Interface for accessing authenticated user information.
 *
 * Implementations can retrieve this from the session to access OAuth2 token details.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
interface AuthenticatedUserInterface
{
    /**
     * Get the access token for the authenticated user.
     */
    public function getAccessToken(): ?AccessTokenInterface;

    /**
     * Check if the user is authenticated.
     */
    public function isAuthenticated(): bool;

    /**
     * Get the user subject (unique identifier).
     */
    public function getSubject(): ?string;

    /**
     * Check if the authenticated user has a specific scope.
     */
    public function hasScope(string $scope): bool;
}

