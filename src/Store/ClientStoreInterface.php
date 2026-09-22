<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use InvalidArgumentException;
use Naf\OAuth\Server\Model\Client;

/**
 * The registered client applications.
 *
 * Registrations are administrative data, not configuration: they arrive one at a
 * time, they are revoked one at a time, and a growing list of them has no
 * business in a file that gets deployed.
 */
interface ClientStoreInterface
{
    public function find(string $clientId): ?Client;

    /**
     * Register an application.
     *
     * @param list<string> $redirectUris
     * @param list<string> $grants
     * @param list<string> $scopes
     * @param list<string> $audiences
     * @return array{0: Client, 1: string|null} The client, and its secret — shown once, stored hashed.
     */
    public function register(
        string $name,
        array $redirectUris,
        array $grants,
        array $scopes,
        bool $confidential,
        array $audiences = [],
    ): array;

    /**
     * Give a client a new secret, without giving it a new identity.
     *
     * The whole difficulty of changing a client secret is that the two sides
     * change at different moments: it is new here before it is new in whatever
     * deployment uses it. So the one it replaces keeps working for $overlap
     * seconds, and an overlap of zero ends it at once — which is what a leak
     * calls for, downtime included.
     *
     * Rotating does not touch the client id, the registration or anything already
     * issued. That is the difference between rotating a secret and replacing a
     * client, and it is why this exists: replacing one means editing every
     * configuration that names it.
     *
     * @return array{0: Client, 1: string} The client, and its new secret — shown once, stored hashed.
     * @throws InvalidArgumentException when there is no such client, or it keeps no secret.
     */
    public function rotateSecret(string $clientId, int $overlap): array;

    public function revoke(string $clientId): void;

    /** @return list<Client> */
    public function all(): array;
}
