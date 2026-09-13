<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

use Closure;
use NixPHP\Auth\Identity\IdentityInterface;
use NixPHP\OAuth\Server\Exception\OAuthError;

/**
 * The one place this server asks whether somebody may still sign in.
 *
 * Every path that speaks for a person — issuing a token, refreshing one, minting
 * an ID token, answering UserInfo, using a token against an API — goes through
 * here, because a deleted or suspended account has to stop working everywhere at
 * once. Scattering that question meant answering it in some places and not
 * others, and the places that skipped it were the ones that assert identity.
 *
 * The answer comes from nixphp/auth, through the same reload a session
 * restoration uses. Whether an account is suspended is the account source's
 * decision, exactly as it is for a browser login: a provider that keeps
 * answering for a locked user is a provider that keeps them signed in too.
 */
final readonly class Users
{
    /** @param Closure(string, string): ?IdentityInterface $load */
    public function __construct(private Closure $load) {}

    public function find(string $provider, string $id): ?IdentityInterface
    {
        if ($provider === '' || $id === '') {
            return null;
        }

        return ($this->load)($provider, $id);
    }

    /**
     * The account, or a refusal. Never a stand-in.
     *
     * @throws OAuthError when there is no account left to speak for.
     */
    public function require(string $provider, string $id): IdentityInterface
    {
        return $this->find($provider, $id)
            ?? throw OAuthError::refuse('invalid_grant', 'That account can no longer sign in.');
    }
}
