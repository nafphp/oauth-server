<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

use NixPHP\OAuth\Server\Exception\OAuthError;
use NixPHP\OAuth\Server\Store\TokenStoreInterface;

/**
 * What this server will say about the person behind an access token.
 *
 * A resource endpoint rather than a protocol one: it is reached with a bearer
 * token and answers about whoever that token was issued for. `sub` is always
 * ours and always the same value the ID token carried — a relying party that
 * matched them once must be able to match them again.
 */
final readonly class UserInfoEndpoint
{
    public function __construct(
        private TokenStoreInterface $tokens,
        private Claims $claims,
        private ?Users $users = null,
    ) {}

    /** @return array<string, mixed> */
    public function forAccessToken(#[\SensitiveParameter] ?string $accessToken): array
    {
        $record = $accessToken === null || $accessToken === '' ? null : $this->tokens->inspect($accessToken);

        if ($record === null) {
            throw OAuthError::refuse('invalid_token', 'No usable access token was presented.', 401);
        }

        if (!$record->hasScope('openid')) {
            throw OAuthError::refuse('insufficient_scope', 'This token does not carry the openid scope.', 403);
        }

        if ($record->userProvider === null || $record->userId === null) {
            // A client-credentials token stands for an application. There is
            // nobody to describe, and inventing one would be the wrong answer.
            throw OAuthError::refuse('invalid_token', 'That token stands for an application, not a person.', 403);
        }

        if ($this->users !== null && $this->users->find($record->userProvider, $record->userId) === null) {
            // An answer of "sub, and nothing else" for a deleted account is still
            // this server confirming they exist. They do not.
            throw OAuthError::refuse('invalid_token', 'That account can no longer sign in.', 403);
        }

        // Left wins, so no claims mapper can replace the subject.
        return ['sub' => $this->tokens->subjectFor($record->userProvider, $record->userId)]
            + $this->claims->forScopes($record->userProvider, $record->userId, $record->scopes);
    }
}
