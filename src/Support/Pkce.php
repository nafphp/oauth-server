<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Support;

use SensitiveParameter;

/** RFC 7636 wire formats for this server's S256-only flow. */
final class Pkce
{
    public static function validVerifier(#[SensitiveParameter] string $verifier): bool
    {
        return preg_match('/\A[A-Za-z0-9._~-]{43,128}\z/', $verifier) === 1;
    }

    public static function validChallenge(string $challenge): bool
    {
        return preg_match('/\A[A-Za-z0-9_-]{43}\z/', $challenge) === 1;
    }
}
