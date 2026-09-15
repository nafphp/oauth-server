<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use Naf\Auth\Identity\IdentityInterface;

/** A local account with permissions, which can also be suspended. */
final class Account implements IdentityInterface
{
    /** @param list<string> $permissions */
    public function __construct(
        private readonly string $id,
        private readonly array $permissions = [],
        public bool $active = true,
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->id;
    }

    public function getRoles(): iterable
    {
        return [];
    }

    public function getPermissions(): iterable
    {
        return $this->permissions;
    }
}
