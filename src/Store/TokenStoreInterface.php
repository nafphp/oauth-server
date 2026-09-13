<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use Naf\OAuth\Server\Model\{AuthorizationRequest, Client, IssuedTokens, TokenRecord};

/**
 * Everything the server issues, and the operations that have to be indivisible.
 *
 * The methods here are whole operations rather than row-level reads and writes,
 * because that is the only level at which they can be correct: redeeming a code
 * and issuing the tokens that come from it is one step or it is a bug, and no
 * caller should be able to get that wrong by holding the pieces differently.
 */
interface TokenStoreInterface
{
    /** A stable public identifier for an account, created once and never reused. */
    public function subjectFor(string $userProvider, string $userId): string;

    /** Park a validated authorization request until somebody consents to it. */
    public function storeRequest(AuthorizationRequest $request, int $ttl): string;

    /**
     * Take it back out, for the same browser and the same person who left it.
     *
     * @throws \Naf\OAuth\Server\Exception\OAuthError when it is gone, expired, or somebody else's.
     */
    public function consumeRequest(string $id, string $sessionId, string $userProvider, string $userId): AuthorizationRequest;

    /** Issue the authorization code for a consented request. Returns the code itself. */
    public function issueCode(AuthorizationRequest $request, int $ttl): string;

    /** Exchange a code for tokens, once, checking every binding it carries. */
    public function redeem(
        #[\SensitiveParameter] string $code,
        Client $client,
        ?string $redirectUri,
        #[\SensitiveParameter] string $verifier,
        int $accessTtl,
        int $refreshTtl,
    ): IssuedTokens;

    /**
     * Exchange a refresh token for a new pair, invalidating the old one.
     *
     * @param list<string>|null $scopes Narrower than what was granted, or null to keep it.
     */
    public function rotate(
        #[\SensitiveParameter] string $refreshToken,
        Client $client,
        int $accessTtl,
        int $refreshTtl,
        ?array $scopes = null,
    ): IssuedTokens;

    /**
     * A token for the application itself. No person, no refresh token.
     *
     * @param list<string> $scopes
     */
    public function issueForClient(Client $client, array $scopes, string $audience, int $accessTtl): IssuedTokens;

    /** What a bearer token is, or null when it is unknown, expired or revoked. */
    public function inspect(#[\SensitiveParameter] string $accessToken): ?TokenRecord;

    /** Withdraw a token, and whatever else came from the same authorization. */
    public function revoke(#[\SensitiveParameter] string $token, Client $client): void;
}
