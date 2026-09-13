<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Model;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * One key this server signs ID tokens with.
 *
 * The private half stays in the file it came from and is only ever read to sign.
 * The public half is published, as a JWK, under the same key id — which is how a
 * relying party that cached the key set yesterday knows to fetch it again today.
 */
final readonly class SigningKey
{
    public function __construct(
        public string $id,
        private string $privateKey,
    ) {}

    public function pem(): string
    {
        return $this->privateKey;
    }

    /**
     * The public half, in the shape a JWKS publishes.
     *
     * @return array<string, string>
     */
    public function jwk(): array
    {
        $key = openssl_pkey_get_private($this->privateKey);

        if (!$key instanceof OpenSSLAsymmetricKey) {
            throw new RuntimeException('Signing key ' . $this->id . ' cannot be read.');
        }

        $details = openssl_pkey_get_details($key);

        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException('Signing key ' . $this->id . ' is not an RSA key.');
        }

        return [
            'kty' => 'RSA',
            'kid' => $this->id,
            'use' => 'sig',
            'alg' => 'RS256',
            'n'   => self::base64url((string) $details['rsa']['n']),
            'e'   => self::base64url((string) $details['rsa']['e']),
        ];
    }

    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
