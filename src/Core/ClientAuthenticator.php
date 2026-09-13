<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

use NixPHP\Auth\Support\PasswordHasher;
use NixPHP\OAuth\Server\Exception\OAuthError;
use NixPHP\OAuth\Server\Model\Client;
use NixPHP\OAuth\Server\Store\ClientStoreInterface;

/**
 * Which client is making this request, and whether it has proved it.
 *
 * Secrets are checked with the same PasswordHasher nixphp/auth uses for people,
 * which is also what makes an unknown client and a wrong secret cost the same.
 *
 * Both forms RFC 6749 §2.3.1 describes are accepted, but never both at once: a
 * request carrying an Authorization header is authenticated by that header, and
 * credentials in the body are then a contradiction rather than a fallback.
 *
 * A public client has no secret and proves nothing here — it is identified, not
 * authenticated, and what protects its exchange is PKCE. Which is exactly why a
 * public client presenting a secret is refused: something is wrong with either
 * the registration or the request, and guessing which is not our job.
 *
 * While a secret is being rotated there are two valid ones, because the new
 * secret exists here before it exists in the deployment that uses it. Both are
 * accepted until the overlap lapses; see Client::previousSecretIsLive().
 */
final readonly class ClientAuthenticator
{
    public function __construct(
        private ClientStoreInterface $clients,
        private PasswordHasher $hasher,
    ) {}

    /** @param array<string, mixed> $body */
    public function authenticate(array $body, ?string $authorizationHeader): Client
    {
        [$id, $secret] = $this->credentials($body, $authorizationHeader);

        if ($id === null) {
            throw OAuthError::refuse('invalid_client', 'The request names no client.', 401);
        }

        $client = $this->clients->find($id);

        if ($client === null) {
            // Verified against a decoy so that an unknown client costs the same as
            // a wrong secret. Otherwise the response time answers "does this client
            // exist" for anybody who asks often enough.
            $this->hasher->verify($secret ?? '', null);

            throw OAuthError::refuse('invalid_client', 'Unknown client.', 401);
        }

        if ($client->isConfidential()) {
            if (!$this->accepts($client, $secret ?? '')) {
                throw OAuthError::refuse('invalid_client', 'Client authentication failed.', 401);
            }

            return $client;
        }

        if ($secret !== null && $secret !== '') {
            throw OAuthError::refuse('invalid_client', 'This client is registered as public and has no secret.', 401);
        }

        return $client;
    }

    /**
     * Whether this is a secret the client may present right now.
     *
     * During a rotation that is two different values. The one being replaced is
     * only tried once the current one has failed, so an open rotation costs a
     * second verification and a closed one costs nothing — which does tell
     * somebody already guessing secrets at a known client that a rotation is
     * under way. That is a much smaller thing to give away than doubling the
     * cost of every token request, for every client, for as long as the server
     * runs; hashing is deliberately expensive here.
     */
    private function accepts(Client $client, string $secret): bool
    {
        if ($this->hasher->verify($secret, $client->secretHash)) {
            return true;
        }

        return $client->previousSecretIsLive()
            && $this->hasher->verify($secret, $client->previousSecretHash);
    }

    /**
     * @param array<string, mixed> $body
     * @return array{0: string|null, 1: string|null}
     */
    private function credentials(array $body, ?string $authorizationHeader): array
    {
        if ($authorizationHeader !== null && stripos($authorizationHeader, 'basic ') === 0) {
            if (isset($body['client_secret'])) {
                throw OAuthError::refuse('invalid_request', 'Use one client authentication method, not two.', 401);
            }

            $decoded = base64_decode(substr($authorizationHeader, 6), true);

            if ($decoded === false || !str_contains($decoded, ':')) {
                throw OAuthError::refuse('invalid_client', 'Malformed client credentials.', 401);
            }

            [$id, $secret] = explode(':', $decoded, 2);

            // Both halves are form-encoded before the colon is added, so both are
            // decoded again here. A secret containing a colon survives that.
            return [rawurldecode($id), rawurldecode($secret)];
        }

        return [
            self::text($body, 'client_id'),
            self::text($body, 'client_secret'),
        ];
    }

    /** @param array<string, mixed> $body */
    private static function text(array $body, string $key): ?string
    {
        $value = $body[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
