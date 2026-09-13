<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Controllers;

use Naf\OAuth\Server\Core\TokenEndpoint;
use Naf\OAuth\Server\Exception\OAuthError;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use function Naf\app;
use function Naf\json;
use function Naf\response;

/**
 * The endpoints a program calls: token, revocation, introspection.
 *
 * Every answer carries no-store, because what passes through here is a
 * credential and a cache that keeps one is a credential somebody else can read.
 * Errors are JSON in the shape RFC 6749 §5.2 describes — never a redirect, never
 * an HTML error page.
 */
final class TokenController
{
    public function issue(): ResponseInterface
    {
        return $this->answer(fn(TokenEndpoint $endpoint, array $body, ?string $authorization): ResponseInterface
            => self::ok($endpoint->issue($body, $authorization)->body()));
    }

    public function revoke(): ResponseInterface
    {
        return $this->answer(function (TokenEndpoint $endpoint, array $body, ?string $authorization): ResponseInterface {
            $endpoint->revoke($body, $authorization);

            // RFC 7009 §2.2: an unknown token is a successful revocation. Anything
            // else would make this a way of asking which tokens exist.
            return response('', 200, self::HEADERS);
        });
    }

    public function introspect(): ResponseInterface
    {
        return $this->answer(fn(TokenEndpoint $endpoint, array $body, ?string $authorization): ResponseInterface
            => self::ok($endpoint->introspect($body, $authorization)));
    }

    // ---------------------------------------------------------------- Internals

    private const array HEADERS = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'];

    /** @param callable(TokenEndpoint, array<string, mixed>, ?string): ResponseInterface $handle */
    private function answer(callable $handle): ResponseInterface
    {
        $request = app()->container()->get(ServerRequestInterface::class);
        $body    = $request->getParsedBody();
        $header  = $request->getHeaderLine('Authorization');

        try {
            return $handle(
                app()->container()->get(TokenEndpoint::class),
                is_array($body) ? $body : [],
                $header === '' ? null : $header,
            );
        } catch (OAuthError $e) {
            $headers = self::HEADERS;

            if ($e->status === 401) {
                // RFC 6749 §5.2: a failed client authentication says how to try again.
                $headers['WWW-Authenticate'] = 'Basic realm="oauth"';
            }

            return json($e->body(), $e->status, $headers);
        }
    }

    /** @param array<string, mixed> $body */
    private static function ok(array $body): ResponseInterface
    {
        return json($body, 200, self::HEADERS);
    }
}
