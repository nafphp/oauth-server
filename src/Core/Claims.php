<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Core;

use Closure;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Identity\UserInterface;

/**
 * What this server is willing to say about a person, filtered by what they agreed to.
 *
 * A user model that implements `UserInterface` already says what may be shown
 * about it — that is what `UserProfile` is for — so the ordinary case needs no
 * configuration at all. The same profile that a consent screen shows is the one
 * released here, which is the point: one answer to "what may be said about this
 * person", not one per consumer.
 *
 * A mapper stays available for anything the profile does not cover, and it adds
 * rather than replaces. Either way this decides what may actually be released:
 * the scopes OpenID Connect defines say which claim belongs to which, and
 * anything outside that list is dropped rather than passed along — including
 * whatever a mapper returns by accident.
 *
 * With neither, an ID token still says who somebody is. `sub` is the whole of
 * what OpenID Connect requires.
 */
final readonly class Claims
{
    /** OpenID Connect Core §5.4. */
    private const array BY_SCOPE = [
        'profile' => [
            'name', 'family_name', 'given_name', 'middle_name', 'nickname',
            'preferred_username', 'profile', 'picture', 'website', 'gender',
            'birthdate', 'zoneinfo', 'locale', 'updated_at',
        ],
        'email'   => ['email', 'email_verified'],
        'phone'   => ['phone_number', 'phone_number_verified'],
        'address' => ['address'],
    ];

    /**
     * @param (Closure(IdentityInterface): array<string, mixed>)|null $mapper
     * @param Closure(string, string): ?IdentityInterface $load
     */
    public function __construct(
        private ?Closure $mapper,
        private Closure $load,
    ) {
    }

    /**
     * @param list<string> $scopes
     * @return array<string, mixed>
     */
    public function forScopes(string $userProvider, string $userId, array $scopes): array
    {
        $user = ($this->load)($userProvider, $userId);

        if ($user === null) {
            // Deleted or suspended between issuing and asking. Saying nothing is
            // the honest answer; inventing something would be worse.
            return [];
        }

        $available = $user instanceof UserInterface ? $user->getProfile()->claims() : [];

        if ($this->mapper !== null) {
            // An addition, not a replacement: a mapper fills gaps the contract
            // does not cover rather than quietly redefining name and email.
            $available = array_merge($available, ($this->mapper)($user));
        }

        $released = [];

        foreach ($scopes as $scope) {
            foreach (self::BY_SCOPE[$scope] ?? [] as $claim) {
                if (array_key_exists($claim, $available)) {
                    $released[$claim] = $available[$claim];
                }
            }
        }

        return $released;
    }

    /** @return list<string> Everything this server could ever release, for discovery. */
    public static function supported(): array
    {
        return array_values(array_unique(array_merge(['sub', 'iss', 'aud', 'exp', 'iat'], ...array_values(self::BY_SCOPE))));
    }
}
