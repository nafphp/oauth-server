<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Controllers;

use Naf\OAuth\Server\Core\Discovery;
use Naf\OAuth\Server\Core\UserInfoEndpoint;
use Naf\OAuth\Server\Exception\OAuthError;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

use function Naf\app;
use function Naf\json;

/**
 * The three endpoints OpenID Connect adds: who this is, what this server does,
 * and the keys to check its signatures with.
 *
 * The last two are public and cacheable — that is the point of them. UserInfo is
 * not: it answers about a person, to whoever holds their token.
 */
final class OpenIdController
{
    private const array PRIVATE_HEADERS = ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache'];
    private const array PUBLIC_HEADERS  = ['Cache-Control' => 'public, max-age=3600'];

    public function userInfo(): ResponseInterface
    {
        $endpoint = app()->container()->get(UserInfoEndpoint::class);

        try {
            return json($endpoint->forAccessToken(self::bearer()), 200, self::PRIVATE_HEADERS);
        } catch (OAuthError $e) {
            // RFC 6750 §3: a resource endpoint says what was wrong in the challenge
            // it sends back, not only in the body.
            return json($e->body(), $e->status, self::PRIVATE_HEADERS + [
                'WWW-Authenticate' => 'Bearer error="' . self::headerSafe($e->error)
                    . '", error_description="' . self::headerSafe($e->description) . '"',
            ]);
        }
    }

    public function configuration(): ResponseInterface
    {
        return json(self::discovery()->document(), 200, self::PUBLIC_HEADERS);
    }

    public function keys(): ResponseInterface
    {
        return json(self::discovery()->keys(), 200, self::PUBLIC_HEADERS);
    }

    // ---------------------------------------------------------------- Internals

    private static function discovery(): Discovery
    {
        return app()->container()->get(Discovery::class);
    }

    private static function bearer(): ?string
    {
        $header = app()->container()->get(ServerRequestInterface::class)->getHeaderLine('Authorization');

        if (stripos($header, 'bearer ') !== 0) {
            return null;
        }

        $token = trim(substr($header, 7));

        return $token === '' ? null : $token;
    }

    /** A quote or a newline in a header value is how a header stops being one value. */
    private static function headerSafe(string $value): string
    {
        return trim((string) preg_replace('/[^\x20-\x21\x23-\x5B\x5D-\x7E]/', ' ', $value));
    }
}
