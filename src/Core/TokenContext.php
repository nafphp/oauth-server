<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Core;

use Closure;
use Naf\Auth\Auth;
use Naf\Auth\Exceptions\ForbiddenException;
use Naf\Auth\Exceptions\UnauthenticatedException;
use Naf\Auth\Identity\IdentityInterface;
use Naf\OAuth\Server\Model\TokenRecord;

/**
 * What the bearer token on this request allows.
 *
 * This is a separate world from `auth()`, on purpose. There is no path here that
 * reaches a session, so an expired, revoked or invented token cannot quietly fall
 * back to whoever happens to be signed in with a cookie. A request with no usable
 * token has no usable token, whatever else it carries.
 *
 * Two things have to hold before anything is allowed, and both are checked every
 * time rather than once at issue:
 *
 * - the **token** carries the scope — what the person agreed this application may
 *   do on their behalf;
 * - the **person** still holds the permission behind it — what they may do at all.
 *
 * So a read-only token stays read-only in the hands of an administrator, and
 * somebody demoted this morning loses access this afternoon rather than when
 * their token happens to expire.
 */
final class TokenContext
{
    private ?Auth $permissions       = null;
    private ?IdentityInterface $user = null;
    private bool $loaded             = false;

    /** @param Closure(string, string): ?IdentityInterface $load */
    public function __construct(
        private readonly ?TokenRecord $record,
        private readonly ScopePolicy $policy,
        private readonly Closure $load,
    ) {
    }

    public function active(): bool
    {
        return $this->record !== null;
    }

    public function clientId(): ?string
    {
        return $this->record?->clientId;
    }

    /** True for a client-credentials token: an application, with nobody behind it. */
    public function isApplication(): bool
    {
        return $this->record?->isApplication() ?? false;
    }

    /** @return list<string> */
    public function scopes(): array
    {
        return $this->record === null ? [] : $this->record->scopes;
    }

    /** Whether the token carries these scopes, saying nothing about who holds what. */
    public function hasScope(string ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!($this->record?->hasScope($scope) ?? false)) {
                return false;
            }
        }

        return true;
    }

    /** Your own model, reloaded through naf/auth. Null for an application token. */
    public function user(): ?IdentityInterface
    {
        if ($this->loaded) {
            return $this->user;
        }

        $this->loaded = true;

        if ($this->record?->userProvider !== null && $this->record->userId !== null) {
            $this->user = ($this->load)($this->record->userProvider, $this->record->userId);
        }

        return $this->user;
    }

    /** Scope and permission together. A plain bool, so guests need no null check first. */
    public function can(string ...$scopes): bool
    {
        foreach ($scopes as $scope) {
            if (!$this->holds($scope)) {
                return false;
            }
        }

        return $scopes !== [] || $this->active();
    }

    /**
     * The same check, as 401 and 403.
     *
     * No token raises 401 — there is something to present and it was not
     * presented. A token that does not reach raises 403.
     */
    public function requireScope(string ...$scopes): void
    {
        if ($this->record === null) {
            throw new UnauthenticatedException();
        }

        foreach ($scopes as $scope) {
            if (!$this->holds($scope)) {
                throw new ForbiddenException();
            }
        }
    }

    // ---------------------------------------------------------------- Internals

    private function holds(string $scope): bool
    {
        if ($this->record === null || !$this->record->hasScope($scope)) {
            return false;
        }

        if ($this->record->isApplication()) {
            // An application stands for nobody, so there is no second set of
            // permissions to satisfy — its registration is the whole answer.
            return true;
        }

        $user = $this->user();

        if ($user === null) {
            // Deleted, suspended, or its source is gone. The token outlives the
            // account only until somebody tries to use it.
            return false;
        }

        $permission = $this->policy->permission($scope);

        return $permission === null || $this->permissionsOf($user)->can($permission);
    }

    /**
     * The permission question is answered by naf/auth, on an instance with no
     * store and no providers: it holds one identity for the length of this
     * request and can reach nothing else. Same implementation as everywhere in
     * the application, none of the session it usually comes with.
     */
    private function permissionsOf(IdentityInterface $user): Auth
    {
        if ($this->permissions === null) {
            $this->permissions = new Auth();
            $this->permissions->setIdentity($user);
        }

        return $this->permissions;
    }
}
