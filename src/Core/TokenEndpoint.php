<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Core;

use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Model\IssuedTokens;
use Naf\OAuth\Server\Store\TokenStoreInterface;

/**
 * The token, revocation and introspection endpoints.
 *
 * Everything here happens after the client has authenticated, and everything
 * that could go wrong is a JSON error rather than a redirect: these endpoints are
 * called by a program, never reached by a browser following a link.
 *
 * The grants themselves are thin, and deliberately so. Whether a code may be
 * spent, whether a refresh token is a replay, what dies when it is — all of that
 * is indivisible work and lives in the store, where it can be one transaction.
 * What is left here is the protocol: who is asking, what they asked for, and
 * whether they are allowed to ask it.
 */
final readonly class TokenEndpoint
{
    private const array GRANTS = ['authorization_code', 'refresh_token', 'client_credentials'];

    public function __construct(
        private ClientAuthenticator $authenticator,
        private TokenStoreInterface $tokens,
        private int $accessTtl = 3600,
        private int $refreshTtl = 2592000,

        // Absent until a signing key exists. Without them this is an OAuth2
        // server, which is a complete thing to be — not a broken OIDC one.
        private ?IdTokenIssuer $idTokens = null,
        private ?Claims $claims = null,
        private ?Users $users = null,
    ) {
    }

    /** @param array<string, mixed> $body */
    public function issue(array $body, ?string $authorization): IssuedTokens
    {
        $client = $this->authenticator->authenticate($body, $authorization);
        $grant  = self::text($body, 'grant_type');

        if ($grant === null || !in_array($grant, self::GRANTS, true)) {
            throw OAuthError::refuse('unsupported_grant_type', 'This server does not offer that grant.');
        }

        if (!$client->allows($grant)) {
            throw OAuthError::refuse('unauthorized_client', 'This client may not use the ' . $grant . ' grant.');
        }

        return match ($grant) {
            'authorization_code' => $this->fromCode($client, $body),
            'refresh_token'      => $this->fromRefreshToken($client, $body),
            default              => $this->forClient($client, $body),
        };
    }

    /**
     * RFC 7009: a revocation always answers 200. Saying "no such token" would turn
     * this endpoint into a way of asking whether one exists.
     *
     * @param array<string, mixed> $body
     */
    public function revoke(array $body, ?string $authorization): void
    {
        $client = $this->authenticator->authenticate($body, $authorization);
        $token  = self::text($body, 'token');

        if ($token !== null) {
            $this->tokens->revoke($token, $client);
        }
    }

    /**
     * RFC 7662, for a resource server that runs somewhere else.
     *
     * Not every client may ask: a token is somebody's authorization, and being
     * registered here is not a reason to learn about other people's. The right to
     * introspect is granted at registration like any other.
     *
     * @param array<string, mixed> $body
     * @return array<string, mixed>
     */
    public function introspect(array $body, ?string $authorization): array
    {
        $client = $this->authenticator->authenticate($body, $authorization);

        if (!$client->isConfidential() || !$client->allows('introspection')) {
            // Both halves matter, and the registry refuses the combination that
            // would make the second one meaningless on its own.
            throw OAuthError::refuse('unauthorized_client', 'This client may not introspect tokens.', 401);
        }

        $token  = self::text($body, 'token');
        $record = $token === null ? null : $this->tokens->inspect($token);

        if ($record === null) {
            return ['active' => false];
        }

        $answer = [
            'active'     => true,
            'client_id'  => $record->clientId,
            'scope'      => implode(' ', $record->scopes),
            'token_type' => 'Bearer',
            'exp'        => $record->expiresAt,
        ];

        if ($record->audience !== '') {
            $answer['aud'] = $record->audience;
        }

        if ($record->userProvider !== null && $record->userId !== null) {
            // The public identifier, never the internal pair.
            $answer['sub'] = $this->tokens->subjectFor($record->userProvider, $record->userId);
        }

        return $answer;
    }

    // ---------------------------------------------------------------- Grants

    /** @param array<string, mixed> $body */
    private function fromCode(Client $client, array $body): IssuedTokens
    {
        $code = self::text($body, 'code');

        if ($code === null) {
            throw OAuthError::refuse('invalid_request', 'The request carries no authorization code.');
        }

        $verifier = self::text($body, 'code_verifier');

        if ($verifier === null) {
            throw OAuthError::refuse('invalid_request', 'The request carries no code_verifier.');
        }

        $redirectUri = self::text($body, 'redirect_uri');

        if ($redirectUri === null) {
            // PKCE binds the exchange to the browser that started it; this binds it
            // to where the code was sent. They answer different questions, and
            // RFC 6749 §4.1.3 asks for both.
            throw OAuthError::refuse('invalid_request', 'The request carries no redirect_uri.');
        }

        $issued = $this->tokens->redeem(
            $code,
            $client,
            $redirectUri,
            $verifier,
            $this->accessTtl,
            $this->refreshTtl,
        );
        $issued = $this->forLivingAccount($issued, $client);

        return $this->identify($issued, $client);
    }

    /** @param array<string, mixed> $body */
    private function fromRefreshToken(Client $client, array $body): IssuedTokens
    {
        $token = self::text($body, 'refresh_token');

        if ($token === null) {
            throw OAuthError::refuse('invalid_request', 'The request carries no refresh token.');
        }

        $scopes = self::scopes($body);

        // A refreshed ID token carries no nonce: that one belonged to the login
        // this chain started from. OpenID Connect Core §12.2.
        $issued = $this->tokens->rotate(
            $token,
            $client,
            $this->accessTtl,
            $this->refreshTtl,
            $scopes === [] ? null : $scopes,
        );
        $issued = $this->forLivingAccount($issued, $client);

        return $this->identify($issued, $client);
    }

    /** @param array<string, mixed> $body */
    private function forClient(Client $client, array $body): IssuedTokens
    {
        if (!$client->isConfidential()) {
            // Nothing to authenticate with means nothing to stand for.
            throw OAuthError::refuse('invalid_client', 'A public client cannot act on its own behalf.', 401);
        }

        return $this->tokens->issueForClient(
            $client,
            $client->grantableScopes(self::scopes($body)),
            $client->audience(self::text($body, 'resource')),
            $this->accessTtl,
        );
    }

    /**
     * Refuse to speak for somebody who is no longer there.
     *
     * Checked after the store has issued, because only then is it known whose
     * grant this was — so whatever was just issued is withdrawn again. Nothing
     * usable escapes, and the authorization ends here rather than surviving as a
     * refresh token that mints fresh identity assertions for a deleted account.
     */
    private function forLivingAccount(IssuedTokens $issued, Client $client): IssuedTokens
    {
        if ($this->users === null || $issued->userProvider === null || $issued->userId === null) {
            return $issued;
        }

        if ($this->users->find($issued->userProvider, $issued->userId) !== null) {
            return $issued;
        }

        $this->tokens->revoke($issued->refreshToken ?? $issued->accessToken, $client);

        throw OAuthError::refuse('invalid_grant', 'That account can no longer sign in.');
    }

    /**
     * Add an ID token when the person asked for one.
     *
     * `openid` in the granted scope is the whole condition: OpenID Connect is
     * something a client opts into per request, not a mode the server is in.
     */
    private function identify(IssuedTokens $issued, Client $client): IssuedTokens
    {
        if ($this->idTokens === null
            || $issued->userProvider === null
            || $issued->userId === null
            || !in_array('openid', $issued->scopes(), true)) {
            return $issued;
        }

        return $issued->withIdToken($this->idTokens->issue(
            subject: $this->tokens->subjectFor($issued->userProvider, $issued->userId),
            audience: $client->id,
            nonce: $issued->nonce,
            claims: $this->claims?->forScopes($issued->userProvider, $issued->userId, $issued->scopes()) ?? [],
        ));
    }

    // ---------------------------------------------------------------- Internals

    /**
     * @param array<string, mixed> $body
     * @return list<string>
     */
    private static function scopes(array $body): array
    {
        $scope = self::text($body, 'scope');

        return $scope === null
            ? []
            : array_values(array_filter(explode(' ', $scope), static fn(string $s): bool => $s !== ''));
    }

    /** @param array<string, mixed> $body */
    private static function text(array $body, string $key): ?string
    {
        $value = $body[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
