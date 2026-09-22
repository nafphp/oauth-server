<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Core;

use Naf\OAuth\Server\Store\KeyStoreInterface;

/**
 * The metadata a relying party reads instead of being configured by hand.
 *
 * It describes what this server actually does, not what the specification allows:
 * one response type, three grants, S256 only. Saying less than is true costs
 * nothing; saying more is how interoperability problems begin.
 *
 * There is no field here for the service's display name. OpenID Connect defines
 * none, so what a relying party shows comes from its own configuration — which is
 * why `oauth_server:name` is documented as display only.
 */
final readonly class Discovery
{
    public function __construct(
        private string $issuer,
        private ScopePolicy $policy,
        private KeyStoreInterface $keys,
    ) {
    }

    /** @return array<string, mixed> */
    public function document(): array
    {
        $base = rtrim($this->issuer, '/');

        $document = [
            'issuer'                                => $base,
            'authorization_endpoint'                => $base . '/oauth/authorize',
            'token_endpoint'                        => $base . '/oauth/token',
            'revocation_endpoint'                   => $base . '/oauth/revoke',
            'introspection_endpoint'                => $base . '/oauth/introspect',
            'response_types_supported'              => ['code'],
            'response_modes_supported'              => ['query'],
            'grant_types_supported'                 => ['authorization_code', 'refresh_token', 'client_credentials'],
            'code_challenge_methods_supported'      => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'scopes_supported'                      => $this->policy->names(),
        ];

        // Without a signing key there are no ID tokens, and a document that
        // advertised them would be describing a server that cannot answer.
        if ($this->keys->has()) {
            $document['userinfo_endpoint']                     = $base . '/oauth/userinfo';
            $document['jwks_uri']                              = $base . '/.well-known/jwks.json';
            $document['subject_types_supported']               = ['public'];
            $document['id_token_signing_alg_values_supported'] = ['RS256'];
            $document['claims_supported']                      = Claims::supported();
        }

        return $document;
    }

    /** @return array{keys: list<array<string, string>>} */
    public function keys(): array
    {
        return ['keys' => array_map(static fn($key): array => $key->jwk(), $this->keys->all())];
    }
}
