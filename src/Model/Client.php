<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Model;

use Naf\OAuth\Server\Exception\OAuthError;

/**
 * A registered client application.
 *
 * Everything a client is allowed to do is decided here, from data an
 * administrator entered — never from what the request asks for. The two methods
 * that matter are the two that attackers reach for: which redirect URI is
 * acceptable, and which scopes may be granted.
 */
final readonly class Client
{
    /**
     * @param list<string> $redirectUris Exact URIs, as registered.
     * @param list<string> $grants
     * @param list<string> $scopes
     * @param list<string> $audiences Empty means the server's own API.
     * @param string|null $previousSecretHash The secret this one replaced, while it is still accepted.
     * @param int|null $previousSecretExpiresAt When that stops being true.
     */
    public function __construct(
        public string $id,
        public string $name,
        public ?string $secretHash,
        public array $redirectUris,
        public array $grants,
        public array $scopes,
        public array $audiences = [],
        public ?string $previousSecretHash = null,
        public ?int $previousSecretExpiresAt = null,
    ) {
    }

    /** A client that can keep a secret authenticates with it; a public one uses PKCE alone. */
    public function isConfidential(): bool
    {
        return $this->secretHash !== null;
    }

    /**
     * Whether the secret this one replaced may still be presented.
     *
     * Rotating a client secret is not one act but two, with somebody else's
     * deployment in between: the new secret exists here before it exists there.
     * Without an overlap the only way to change a secret is to break the client
     * until it is redeployed, which is why in practice nobody changes it.
     *
     * The window is a deadline, not a state to be tidied up: it lapses on its
     * own, and nothing has to run for the old secret to stop working.
     */
    public function previousSecretIsLive(?int $now = null): bool
    {
        return $this->previousSecretHash !== null
            && $this->previousSecretExpiresAt !== null
            && $this->previousSecretExpiresAt > ($now ?? time());
    }

    public function allows(string $grant): bool
    {
        return in_array($grant, $this->grants, true);
    }

    /**
     * The redirect URI this request may use.
     *
     * Exact string comparison against what was registered, and nothing else. No
     * prefix, no suffix, no ignored query, no wildcard — every one of those has
     * been somebody's account-takeover bug. A request that names no URI is only
     * answered when there is exactly one registered, because otherwise picking
     * for them means guessing.
     */
    public function redirectUri(?string $requested): string
    {
        if ($requested === null || $requested === '') {
            if (count($this->redirectUris) === 1) {
                return $this->redirectUris[0];
            }

            throw OAuthError::refuse('invalid_request', 'This client has several redirect URIs, so the request has to name one.');
        }

        foreach ($this->redirectUris as $registered) {
            if (hash_equals($registered, $requested)) {
                return $registered;
            }
        }

        throw OAuthError::refuse('invalid_request', 'That redirect URI is not registered for this client.');
    }

    /**
     * Narrow a scope request to what this client may ask for.
     *
     * Asking for nothing is answered with everything the client is allowed, which
     * is the predictable reading of RFC 6749 §3.3. Asking for something it is not
     * allowed is refused rather than quietly trimmed: a client that believes it
     * got a scope it did not get is a client that fails later and further away.
     *
     * @param list<string> $requested
     * @return list<string>
     */
    public function grantableScopes(array $requested): array
    {
        if ($requested === []) {
            return $this->scopes;
        }

        foreach ($requested as $scope) {
            if (!in_array($scope, $this->scopes, true)) {
                throw OAuthError::redirect('invalid_scope', 'This client may not ask for "' . $scope . '".');
            }
        }

        return array_values(array_unique($requested));
    }

    /** The API a token is for. Empty means this server's own. */
    public function audience(?string $requested): string
    {
        if ($requested === null || $requested === '') {
            return $this->audiences[0] ?? '';
        }

        if (!in_array($requested, $this->audiences, true)) {
            throw OAuthError::redirect('invalid_target', 'This client may not ask for "' . $requested . '".');
        }

        return $requested;
    }
}
