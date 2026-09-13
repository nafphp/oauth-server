<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

use Closure;
use NixPHP\OAuth\Server\Store\TokenStoreInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Turns the Authorization header of this request into what it allows.
 *
 * Looked up once per request. A header that is absent, malformed or not a Bearer
 * is the same as one naming a token we have never issued: no context, and
 * nothing to fall back on. So is a perfectly valid token that was granted for
 * some other API — scopes mean different things behind different doors, and a
 * token is only ever a key to the one it was issued for.
 */
final class ResourceServer
{
    private ?TokenContext $context = null;

    /**
     * @param Closure(string, string): ?\NixPHP\Auth\Identity\IdentityInterface $load
     * @param string $audience What this API is called. Empty means the issuing server's own API.
     */
    public function __construct(
        private readonly TokenStoreInterface $tokens,
        private readonly ScopePolicy $policy,
        private readonly Closure $load,
        private readonly ServerRequestInterface $request,
        private readonly string $audience = '',
    ) {}

    public function context(): TokenContext
    {
        if ($this->context !== null) {
            return $this->context;
        }

        $bearer = self::bearer($this->request->getHeaderLine('Authorization'));
        $record = $bearer === null ? null : $this->tokens->inspect($bearer);

        // A token says which API it is for. One granted for a different API is
        // not a weaker token here — it is not a token here at all.
        if ($record !== null && !hash_equals($this->audience, $record->audience)) {
            $record = null;
        }

        return $this->context = new TokenContext($record, $this->policy, $this->load);
    }

    private static function bearer(string $header): ?string
    {
        if (stripos($header, 'bearer ') !== 0) {
            return null;
        }

        $token = trim(substr($header, 7));

        return $token === '' ? null : $token;
    }
}
