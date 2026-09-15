<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use Naf\OAuth\Server\Model\SigningKey;
use RuntimeException;

/**
 * The keys this server signs with, and the ones it still publishes.
 *
 * Rotation is the reason these are two different questions. New tokens are
 * signed with one key; every key that may still appear in a token somebody is
 * holding has to stay published, or rotating would invalidate tokens that have
 * not expired yet.
 */
interface KeyStoreInterface
{
    /** @throws RuntimeException when none has been generated yet. */
    public function active(): SigningKey;

    public function has(): bool;

    /** @return list<SigningKey> Everything a relying party might still need. */
    public function all(): array;

    /** Create a new key and make it the one that signs from now on. */
    public function generate(): SigningKey;

    /**
     * Forget keys older than this, keeping the active one whatever its age.
     *
     * @return list<string> The key ids that were removed.
     */
    public function prune(int $maximumAge): array;
}
