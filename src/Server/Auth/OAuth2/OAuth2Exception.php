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

use Mcp\Exception\Exception;

/**
 * Exception thrown for OAuth2 authentication/authorization errors.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class OAuth2Exception extends Exception
{
    public const ERROR_INVALID_TOKEN = 'invalid_token';
    public const ERROR_EXPIRED_TOKEN = 'expired_token';
    public const ERROR_INSUFFICIENT_SCOPE = 'insufficient_scope';
    public const ERROR_INVALID_REQUEST = 'invalid_request';
    public const ERROR_ACCESS_DENIED = 'access_denied';
    public const ERROR_SERVER_ERROR = 'server_error';

    public function __construct(
        string $message,
        private readonly string $error = self::ERROR_INVALID_TOKEN,
        private readonly ?string $errorDescription = null,
        private readonly int $httpStatusCode = 401,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public function getError(): string
    {
        return $this->error;
    }

    public function getErrorDescription(): ?string
    {
        return $this->errorDescription;
    }

    public function getHttpStatusCode(): int
    {
        return $this->httpStatusCode;
    }

    /**
     * Get WWW-Authenticate header value for the error response.
     */
    public function getWwwAuthenticateHeader(?string $realm = null): string
    {
        $parts = ['Bearer'];

        if (null !== $realm) {
            $parts[] = \sprintf('realm="%s"', $realm);
        }

        $parts[] = \sprintf('error="%s"', $this->error);

        if (null !== $this->errorDescription) {
            $parts[] = \sprintf('error_description="%s"', addslashes($this->errorDescription));
        }

        return implode(', ', $parts);
    }

    public static function invalidToken(string $reason = 'Token is invalid'): self
    {
        return new self(
            message: $reason,
            error: self::ERROR_INVALID_TOKEN,
            errorDescription: $reason,
            httpStatusCode: 401,
        );
    }

    public static function expiredToken(): self
    {
        return new self(
            message: 'The access token has expired',
            error: self::ERROR_EXPIRED_TOKEN,
            errorDescription: 'The access token has expired',
            httpStatusCode: 401,
        );
    }

    public static function insufficientScope(array $requiredScopes): self
    {
        $scopeStr = implode(' ', $requiredScopes);

        return new self(
            message: \sprintf('Insufficient scope. Required: %s', $scopeStr),
            error: self::ERROR_INSUFFICIENT_SCOPE,
            errorDescription: \sprintf('The access token requires scope: %s', $scopeStr),
            httpStatusCode: 403,
        );
    }

    public static function missingToken(): self
    {
        return new self(
            message: 'No access token provided',
            error: self::ERROR_INVALID_REQUEST,
            errorDescription: 'The request is missing a required access token',
            httpStatusCode: 401,
        );
    }

    public static function serverError(string $message, ?\Throwable $previous = null): self
    {
        return new self(
            message: $message,
            error: self::ERROR_SERVER_ERROR,
            errorDescription: 'An internal error occurred during authentication',
            httpStatusCode: 500,
            previous: $previous,
        );
    }
}

