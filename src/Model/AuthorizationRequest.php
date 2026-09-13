<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Model;

/**
 * An authorization request that has already been checked, waiting for consent.
 *
 * It exists as a record rather than as query parameters because consent must be
 * given for the request the server validated, not for whatever the browser posts
 * back afterwards. Nothing here is ever re-read from the consent form.
 *
 * `audience` is the API the person is authorizing access to. It is settled here
 * and carried for the life of the grant — an empty string meaning this server's
 * own API.
 */
final readonly class AuthorizationRequest
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $clientId,
        public string $redirectUri,
        public array $scopes,
        public string $state,
        public string $codeChallenge,
        public ?string $nonce,
        public string $audience,
        public string $sessionId,
        public string $userProvider,
        public string $userId,
    ) {}

    public function scope(): string
    {
        return implode(' ', $this->scopes);
    }
}
