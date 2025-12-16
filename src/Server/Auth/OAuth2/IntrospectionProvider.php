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

use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * OAuth2 provider that validates tokens via RFC 7662 Token Introspection.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class IntrospectionProvider extends AbstractOAuth2Provider
{
    /**
     * @param string[] $requiredScopes
     */
    public function __construct(
        string $clientId,
        string $clientSecret,
        string $authorizationUrl,
        string $tokenUrl,
        private readonly string $introspectionUrl,
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        array $requiredScopes = [],
        ?string $resourceServer = null,
        ?string $issuer = null,
        private readonly ?string $registrationUrl = null,
        private readonly ?string $externalTokenUrl = null,
        private readonly ?string $externalIntrospectionUrl = null,
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
    }

    public function validateToken(string $token): AccessTokenInterface
    {
        $request = $this->requestFactory->createRequest('POST', $this->introspectionUrl);

        // Add Basic authentication
        $credentials = base64_encode(\sprintf('%s:%s', $this->clientId, $this->clientSecret));
        $request = $request->withHeader('Authorization', \sprintf('Basic %s', $credentials));
        $request = $request->withHeader('Content-Type', 'application/x-www-form-urlencoded');

        $body = http_build_query(['token' => $token, 'token_type_hint' => 'access_token']);
        $request = $request->withBody($this->streamFactory->createStream($body));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (\Throwable $e) {
            throw OAuth2Exception::serverError('Failed to introspect token', $e);
        }

        if (200 !== $response->getStatusCode()) {
            throw OAuth2Exception::serverError(\sprintf(
                'Introspection endpoint returned status %d',
                $response->getStatusCode()
            ));
        }

        try {
            $data = json_decode((string) $response->getBody(), true, 512, \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw OAuth2Exception::serverError('Invalid introspection response', $e);
        }

        if (!isset($data['active']) || true !== $data['active']) {
            throw OAuth2Exception::invalidToken('Token is not active');
        }

        $accessToken = AccessToken::fromClaims($token, $data);

        $this->validateExpiration($accessToken);
        $this->validateScopes($accessToken);

        return $accessToken;
    }

    public function getMetadata(): array
    {
        $metadata = parent::getMetadata();

        // Use external URLs for browser-facing metadata if provided
        if (null !== $this->externalTokenUrl) {
            $metadata['token_endpoint'] = $this->externalTokenUrl;
        }

        $metadata['introspection_endpoint'] = $this->externalIntrospectionUrl ?? $this->introspectionUrl;

        if (null !== $this->registrationUrl) {
            $metadata['registration_endpoint'] = $this->registrationUrl;
        }

        return $metadata;
    }
}

