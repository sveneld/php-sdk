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
 * OAuth2 provider that uses a callback function for token validation.
 *
 * Useful for custom validation logic or integrating with existing authentication systems.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class CallbackTokenValidator extends AbstractOAuth2Provider
{
    /** @var callable(string): AccessTokenInterface */
    private $validator;

    /**
     * @param callable(string): AccessTokenInterface $validator Function that validates token and returns AccessToken
     * @param string[] $requiredScopes
     */
    public function __construct(
        callable $validator,
        string $clientId,
        string $clientSecret,
        string $authorizationUrl,
        string $tokenUrl,
        array $requiredScopes = [],
        ?string $resourceServer = null,
        ?string $issuer = null,
    ) {
        parent::__construct(
            $clientId,
            $clientSecret,
            $authorizationUrl,
            $tokenUrl,
            $requiredScopes,
            $resourceServer,
            $issuer,
        );
        $this->validator = $validator;
    }

    public function validateToken(string $token): AccessTokenInterface
    {
        try {
            $accessToken = ($this->validator)($token);
        } catch (OAuth2Exception $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw OAuth2Exception::invalidToken($e->getMessage());
        }

        $this->validateExpiration($accessToken);
        $this->validateScopes($accessToken);

        return $accessToken;
    }
}

