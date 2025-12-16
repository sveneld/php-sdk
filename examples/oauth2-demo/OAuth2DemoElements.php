<?php

/*
 * This file is part of the official PHP MCP SDK.
 *
 * A collaboration between Symfony and the PHP Foundation.
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Mcp\Example\OAuth2Demo;

use Mcp\Capability\Attribute\McpTool;
use Mcp\Schema\Content\TextContent;
use Mcp\Server\RequestContext;
use Mcp\Server\Session\SessionInterface;

/**
 * MCP Tools that demonstrate OAuth2 authenticated access.
 *
 * These tools show how to access authenticated user information
 * from the session when OAuth2 is enabled.
 *
 * @author Volodymyr Panivko <sveneld300@gmail.com>
 */
class OAuth2DemoElements
{
    /**
     * Get information about the currently authenticated user.
     *
     * This tool demonstrates how to access OAuth2 token information
     * from the MCP session.
     */
    #[McpTool(
        name: 'get_current_user',
        description: 'Get information about the currently authenticated user'
    )]
    public function getCurrentUser(RequestContext $context): TextContent
    {
        // In a real implementation, you would store auth info in the session
        // when the token is validated. For this demo, we show the concept.
        $clientInfo = $context->getSession()->get('client_info');
        $initialized = $context->getSession()->get('initialized', false);

        $info = [
            'session_id' => $context->getSession()->getId()->toRfc4122(),
            'initialized' => $initialized,
            'client_info' => $clientInfo,
            'message' => 'You are authenticated! This tool only works with a valid OAuth2 token.',
        ];

        return new TextContent(json_encode($info, \JSON_PRETTY_PRINT));
    }

    /**
     * A protected resource that requires authentication.
     *
     * This demonstrates a tool that performs actions on behalf of the authenticated user.
     */
    #[McpTool(
        name: 'protected_action',
        description: 'Perform a protected action that requires authentication'
    )]
    public function protectedAction(string $action, RequestContext $context): TextContent
    {
        $timestamp = date('Y-m-d H:i:s');

        $result = [
            'success' => true,
            'action' => $action,
            'performed_at' => $timestamp,
            'session_id' => $context->getSession()->getId()->toRfc4122(),
            'message' => "Protected action '{$action}' executed successfully at {$timestamp}",
        ];

        return new TextContent(json_encode($result, \JSON_PRETTY_PRINT));
    }

    /**
     * List available scopes for the current token.
     *
     * In a real implementation, this would read from the validated token.
     */
    #[McpTool(
        name: 'list_my_scopes',
        description: 'List the OAuth2 scopes available to your access token'
    )]
    public function listMyScopes(RequestContext $context): TextContent
    {
        // This would typically come from the validated token stored in session
        $scopes = [
            'available_scopes' => ['openid', 'profile', 'mcp:read', 'mcp:write'],
            'note' => 'In production, these would be read from the validated access token',
        ];

        return new TextContent(json_encode($scopes, \JSON_PRETTY_PRINT));
    }

    /**
     * Echo back a message - a simple authenticated endpoint.
     */
    #[McpTool(
        name: 'authenticated_echo',
        description: 'Echo back a message (requires authentication)'
    )]
    public function authenticatedEcho(string $message): TextContent
    {
        return new TextContent(\sprintf(
            '🔐 Authenticated echo: %s (at %s)',
            $message,
            date('Y-m-d H:i:s')
        ));
    }
}

