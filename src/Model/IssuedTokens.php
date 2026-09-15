<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Model;

/**
 * What a successful grant hands back.
 *
 * The first five fields are the response RFC 6749 §5.1 describes. The three after
 * them are not: they say who this was issued for and which login it came from, so
 * that the token endpoint can mint an ID token without asking the database a
 * second time. `body()` never emits them.
 */
final readonly class IssuedTokens
{
    public function __construct(
        public string $accessToken,
        public int $expiresIn,
        public string $scope,
        public ?string $refreshToken = null,
        public ?string $idToken = null,
        public ?string $userProvider = null,
        public ?string $userId = null,
        public ?string $nonce = null,
    ) {
    }

    public function withIdToken(string $idToken): self
    {
        return new self(
            $this->accessToken,
            $this->expiresIn,
            $this->scope,
            $this->refreshToken,
            $idToken,
            $this->userProvider,
            $this->userId,
            $this->nonce,
        );
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return array_values(array_filter(explode(' ', $this->scope), static fn(string $s): bool => $s !== ''));
    }

    /** @return array<string, string|int> */
    public function body(): array
    {
        $body = [
            'access_token' => $this->accessToken,
            'token_type'   => 'Bearer',
            'expires_in'   => $this->expiresIn,
            'scope'        => $this->scope,
        ];

        if ($this->refreshToken !== null) {
            $body['refresh_token'] = $this->refreshToken;
        }

        if ($this->idToken !== null) {
            $body['id_token'] = $this->idToken;
        }

        return $body;
    }
}
