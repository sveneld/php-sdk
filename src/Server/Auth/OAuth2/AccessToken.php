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

use Mcp\Server\NativeClock;
use Psr\Clock\ClockInterface;

/**
 * Default implementation of AccessTokenInterface.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class AccessToken implements AccessTokenInterface
{
    private ClockInterface $clock;

    /**
     * @param string[]             $scopes
     * @param array<string, mixed> $claims
     */
    public function __construct(
        private readonly string $token,
        private readonly ?string $subject = null,
        private readonly ?string $clientId = null,
        private readonly array $scopes = [],
        private readonly ?\DateTimeImmutable $expiresAt = null,
        private readonly array $claims = [],
        ?ClockInterface $clock = null,
    ) {
        $this->clock = $clock ?? new NativeClock();
    }

    public function getToken(): string
    {
        return $this->token;
    }

    public function getSubject(): ?string
    {
        return $this->subject;
    }

    public function getClientId(): ?string
    {
        return $this->clientId;
    }

    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function hasScope(string $scope): bool
    {
        return \in_array($scope, $this->scopes, true);
    }

    public function getExpiresAt(): ?\DateTimeImmutable
    {
        return $this->expiresAt;
    }

    public function isExpired(): bool
    {
        if (null === $this->expiresAt) {
            return false;
        }

        return $this->clock->now() > $this->expiresAt;
    }

    public function getClaims(): array
    {
        return $this->claims;
    }

    public function getClaim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    /**
     * Create an AccessToken from JWT claims array.
     *
     * @param array<string, mixed> $claims
     *
     * @throws OAuth2Exception if the exp claim cannot be parsed
     */
    public static function fromClaims(string $token, array $claims, ?ClockInterface $clock = null): self
    {
        $expiresAt = null;
        if (isset($claims['exp'])) {
            if (!is_numeric($claims['exp'])) {
                throw OAuth2Exception::invalidToken('Token exp claim must be a numeric timestamp');
            }

            $parsed = \DateTimeImmutable::createFromFormat('U', (string) $claims['exp']);
            if (false === $parsed) {
                throw OAuth2Exception::invalidToken('Token exp claim could not be parsed as a valid timestamp');
            }

            $expiresAt = $parsed;
        }

        $scopes = [];
        if (isset($claims['scope']) && \is_string($claims['scope'])) {
            $scopes = explode(' ', $claims['scope']);
        } elseif (isset($claims['scopes']) && \is_array($claims['scopes'])) {
            $scopes = $claims['scopes'];
        }

        return new self(
            token: $token,
            subject: $claims['sub'] ?? null,
            clientId: $claims['client_id'] ?? $claims['azp'] ?? null,
            scopes: $scopes,
            expiresAt: $expiresAt,
            claims: $claims,
            clock: $clock,
        );
    }
}

