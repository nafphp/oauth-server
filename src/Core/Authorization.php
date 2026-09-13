<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Core;

use Closure;
use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\AuthorizationRequest;
use Naf\OAuth\Server\Store\{ClientStoreInterface, TokenStoreInterface};

/**
 * The authorization endpoint: check the request, ask the person, issue the code.
 *
 * The order of the checks is the substance of this class, not an implementation
 * detail. Until the redirect URI has been matched against what was registered,
 * **nothing** may be sent back to it — an error redirected to an unverified
 * address is an open redirect with an official-looking error message attached.
 * Everything before that line ends on our own page; everything after it may be
 * reported to the client, which is where `OAuthError::to()` fills in the target.
 *
 * Consent is stored, not carried. The browser gets an opaque request id and
 * nothing else: no client id, no scope, no redirect URI. Whatever comes back is
 * only ever a key to look the validated request up by.
 */
final readonly class Authorization
{
    /** @param Closure(string): bool $holdsPermission */
    public function __construct(
        private ClientStoreInterface $clients,
        private TokenStoreInterface $tokens,
        private ScopePolicy $policy,
        private Closure $holdsPermission,
        private int $consentTtl = 600,
        private int $codeTtl = 60,

        // Whether this server can sign an ID token at all. Offering openid without
        // it means a client asks for OpenID Connect, a person agrees to it, and
        // the token response quietly contains no ID token.
        private bool $signs = false,
    ) {}

    /**
     * @param array<string, mixed> $query
     * @throws OAuthError
     */
    public function begin(array $query, string $sessionId, string $userProvider, string $userId): Consent
    {
        $clientId = self::text($query, 'client_id');

        if ($clientId === null) {
            throw OAuthError::refuse('invalid_request', 'The request names no client.');
        }

        $client = $this->clients->find($clientId);

        if ($client === null) {
            throw OAuthError::refuse('invalid_client', 'Unknown client.');
        }

        $requested = self::text($query, 'redirect_uri');

        if ($requested === null) {
            // Required, even for a client with exactly one registered URI: the
            // same value has to come back at the token endpoint, and a request
            // that never named one cannot be held to it there.
            throw OAuthError::refuse('invalid_request', 'The request has to name a redirect_uri.');
        }

        // Throws without a destination: a URI we cannot vouch for is not a place
        // to send anybody, least of all with our error message in the query string.
        $redirectUri = $client->redirectUri($requested);
        $state       = self::text($query, 'state') ?? '';

        try {
            if (self::text($query, 'response_type') !== 'code') {
                throw OAuthError::redirect('unsupported_response_type', 'This server issues authorization codes.');
            }

            if (!$client->allows('authorization_code')) {
                throw OAuthError::redirect('unauthorized_client', 'This client may not use the authorization code grant.');
            }

            $challenge = self::text($query, 'code_challenge');

            if ($challenge === null) {
                throw OAuthError::redirect('invalid_request', 'PKCE is required: send a code_challenge.');
            }

            if (self::text($query, 'code_challenge_method') !== 'S256') {
                throw OAuthError::redirect('invalid_request', 'Only the S256 code challenge method is accepted.');
            }

            $this->refuseWhatIsNotOffered($query);

            $granted = $this->grant($client->grantableScopes(self::scopes($query)));

            if (!$this->signs && in_array('openid', $granted, true)) {
                throw OAuthError::redirect(
                    'invalid_scope',
                    'This server has no signing key and cannot issue ID tokens. Run "nix oauth:keys:generate".',
                );
            }

            // Which API this is for is settled here and carried for the life of the
            // grant. An empty value means this server's own.
            $audience = $client->audience(self::text($query, 'resource'));

            $id = $this->tokens->storeRequest(new AuthorizationRequest(
                clientId: $client->id,
                redirectUri: $redirectUri,
                scopes: $granted,
                state: $state,
                codeChallenge: $challenge,
                nonce: self::text($query, 'nonce'),
                audience: $audience,
                sessionId: $sessionId,
                userProvider: $userProvider,
                userId: $userId,
            ), $this->consentTtl);

            return new Consent($id, $client->name, array_map(
                fn(string $scope): array => ['scope' => $scope, 'label' => $this->policy->label($scope)],
                $granted,
            ));
        } catch (OAuthError $e) {
            throw $e->to($redirectUri, $state);
        }
    }

    /** Consent given. Returns where to send the browser. */
    public function approve(string $requestId, string $sessionId, string $userProvider, string $userId): string
    {
        $request = $this->tokens->consumeRequest($requestId, $sessionId, $userProvider, $userId);
        $code    = $this->tokens->issueCode($request, $this->codeTtl);

        return self::target($request->redirectUri, ['code' => $code, 'state' => $request->state]);
    }

    /** Consent refused. The client is told so, in the way the specification expects. */
    public function deny(string $requestId, string $sessionId, string $userProvider, string $userId): string
    {
        $request = $this->tokens->consumeRequest($requestId, $sessionId, $userProvider, $userId);

        return self::target($request->redirectUri, [
            'error'             => 'access_denied',
            'error_description' => 'The person declined.',
            'state'             => $request->state,
        ]);
    }

    /**
     * Say no to what this server does not do, rather than proceeding as if it had
     * not been asked.
     *
     * Silently ignoring prompt or max_age is the worst answer available: a relying
     * party that asked for re-authentication and got an ordinary session back has
     * been told something untrue about the person in front of it.
     *
     * @param array<string, mixed> $query
     */
    private function refuseWhatIsNotOffered(array $query): void
    {
        $prompts = explode(' ', self::text($query, 'prompt') ?? '');

        if (in_array('none', $prompts, true)) {
            // Consent is always asked for here, so a request that forbids any
            // interaction can never be satisfied.
            throw OAuthError::redirect('interaction_required', 'This server always asks before granting access.');
        }

        if (in_array('login', $prompts, true)) {
            throw OAuthError::redirect('invalid_request', 'prompt=login is not supported: this server cannot force re-authentication.');
        }

        if (self::text($query, 'max_age') !== null) {
            throw OAuthError::redirect('invalid_request', 'max_age is not supported: this server does not record when somebody last authenticated.');
        }
    }

    // ---------------------------------------------------------------- Internals

    /**
     * Narrow what the client may ask for to what this person actually holds.
     *
     * A scope is granted only when its permission is held right now, so a
     * demotion takes effect the next time anybody authorizes. Narrowing rather
     * than refusing is what RFC 6749 §3.3 expects, and the token response says
     * what was granted — but being left with nothing at all is a refusal, not a
     * silently empty token.
     *
     * @param list<string> $allowed
     * @return list<string>
     */
    private function grant(array $allowed): array
    {
        foreach ($allowed as $scope) {
            if (!$this->policy->knows($scope)) {
                throw OAuthError::redirect('invalid_scope', 'This server does not offer "' . $scope . '".');
            }
        }

        $granted = array_values(array_filter($allowed, function (string $scope): bool {
            $permission = $this->policy->permission($scope);

            // The OpenID Connect scopes guard nothing: they ask to see who
            // somebody is, and the person consenting is the person concerned.
            return $permission === null || ($this->holdsPermission)($permission);
        }));

        if ($allowed !== [] && $granted === []) {
            throw OAuthError::redirect('access_denied', 'This account holds none of the requested permissions.');
        }

        return $granted;
    }

    /** @param array<string, string> $parameters */
    private static function target(string $redirectUri, array $parameters): string
    {
        $parameters = array_filter($parameters, static fn(string $value): bool => $value !== '');

        return $redirectUri
            . (str_contains($redirectUri, '?') ? '&' : '?')
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * @param array<string, mixed> $query
     * @return list<string>
     */
    private static function scopes(array $query): array
    {
        $scope = self::text($query, 'scope');

        return $scope === null
            ? []
            : array_values(array_filter(explode(' ', $scope), static fn(string $s): bool => $s !== ''));
    }

    /** @param array<string, mixed> $query */
    private static function text(array $query, string $key): ?string
    {
        $value = $query[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
