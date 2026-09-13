<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

/**
 * What the scopes this server offers mean, and what they require.
 *
 * A scope is what a client asked for; a permission is what a person holds. They
 * are related but not the same word, and forcing them to be identical would make
 * every API surface leak into the wording of a consent screen. So a scope names
 * the permission it needs, and defaults to its own name when there is nothing to
 * translate.
 */
final readonly class ScopePolicy
{
    /**
     * The scopes OpenID Connect defines, which no application has to configure.
     *
     * None of them requires a permission, and that is not an oversight: they ask
     * to see who somebody is and what their own profile says, not to do anything
     * on their behalf. The person consenting is the person concerned.
     */
    private const array STANDARD = [
        'openid'  => ['label' => 'Confirm who you are', 'permission' => null],
        'profile' => ['label' => 'See your profile', 'permission' => null],
        'email'   => ['label' => 'See your email address', 'permission' => null],
    ];

    /** @param array<string, array<string, mixed>|string> $scopes */
    public function __construct(private array $scopes) {}

    public function knows(string $scope): bool
    {
        return array_key_exists($scope, $this->scopes) || array_key_exists($scope, self::STANDARD);
    }

    /** What a consent screen says about this scope. */
    public function label(string $scope): string
    {
        $entry = $this->scopes[$scope] ?? self::STANDARD[$scope] ?? null;

        if (is_string($entry) && $entry !== '') {
            return $entry;
        }

        $label = is_array($entry) ? ($entry['label'] ?? null) : null;

        return is_string($label) && $label !== '' ? $label : $scope;
    }

    /**
     * The permission somebody must hold for this scope to be granted, and to keep
     * working. Null means none is needed.
     *
     * A configured scope defaults to requiring a permission of its own name,
     * because a scope that guards nothing is almost never what was meant. The
     * standard OpenID Connect scopes are the exception, and say so explicitly.
     */
    public function permission(string $scope): ?string
    {
        if (!array_key_exists($scope, $this->scopes) && array_key_exists($scope, self::STANDARD)) {
            return self::STANDARD[$scope]['permission'];
        }

        $entry = $this->scopes[$scope] ?? null;

        if (is_array($entry) && array_key_exists('permission', $entry)) {
            $permission = $entry['permission'];

            return is_string($permission) && $permission !== '' ? $permission : null;
        }

        return $scope;
    }

    /** @return list<string> Everything on offer, for the discovery document. */
    public function names(): array
    {
        return array_values(array_unique([...array_keys(self::STANDARD), ...array_keys($this->scopes)]));
    }
}
