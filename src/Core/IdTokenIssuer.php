<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

use Firebase\JWT\JWT;
use NixPHP\OAuth\Server\Store\KeyStoreInterface;

/**
 * The one thing this server signs.
 *
 * An ID token is a statement addressed to one application: "the person here is
 * this subject, I said so at this moment, and I was answering the login that
 * carried this nonce." Everything that makes it that statement — issuer, subject,
 * audience, times — is written last, so a claim an application supplies can add
 * to it but never rewrite what it means.
 *
 * Access tokens are opaque on purpose and are not signed. This exists because
 * OpenID Connect defines the ID token as a JWT, not because a signature was
 * wanted somewhere.
 */
final readonly class IdTokenIssuer
{
    public function __construct(
        private KeyStoreInterface $keys,
        private string $issuer,
        private int $ttl = 3600,
    ) {}

    /**
     * @param array<string, mixed> $claims Profile and e-mail claims, already filtered by scope.
     */
    public function issue(string $subject, string $audience, ?string $nonce, array $claims = []): string
    {
        $now = time();

        $protocol = [
            'iss' => $this->issuer,
            'sub' => $subject,
            'aud' => $audience,
            'iat' => $now,
            'exp' => $now + $this->ttl,
        ];

        if ($nonce !== null && $nonce !== '') {
            $protocol['nonce'] = $nonce;
        }

        // Later wins, and the protocol is later: an application's claims mapper
        // cannot quietly change who this token is about or who it is for.
        $payload = array_merge($claims, $protocol);

        $key = $this->keys->active();

        return JWT::encode($payload, $key->pem(), 'RS256', $key->id);
    }
}
