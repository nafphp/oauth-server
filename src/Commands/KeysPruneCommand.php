<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Commands;

use Naf\CLI\Core\AbstractCommand;
use Naf\CLI\Core\Input;
use Naf\CLI\Core\Output;
use Naf\OAuth\Server\Store\KeyStoreInterface;

use function Naf\app;
use function Naf\config;

/**
 * Stop publishing keys that nothing can still be signed with.
 *
 * The age to keep has to be longer than an ID token lives, or this removes a key
 * that somebody is still holding a token from — so the default is derived from
 * the configured lifetime rather than picked. The active key is never removed,
 * however old it is.
 */
class KeysPruneCommand extends AbstractCommand
{
    public const string NAME = 'oauth:keys:prune';

    protected function configure(): void
    {
        $this
            ->setTitle('Prune old signing keys')
            ->setDescription('Remove rotated-out keys whose tokens have all expired.')
            ->addOption('older-than', 'o', expectsValue: true);
    }

    public function run(Input $input, Output $output): int
    {
        $configured = $input->getOption('older-than');
        $lifetime   = (int) config('oauth_server:id_token_ttl', 3600);

        // Twice the lifetime, so a token minted the instant before a rotation is
        // long gone before its key is.
        $age = is_string($configured) && ctype_digit($configured) ? (int) $configured : $lifetime * 2;

        if ($age < $lifetime) {
            $output->writeLine(
                'Keeping keys for less than an ID token lives (' . $lifetime . 's) would break tokens still in use.',
                'error',
            );

            return self::ERROR;
        }

        $removed = app()->container()->get(KeyStoreInterface::class)->prune($age);

        $output->writeLine($removed === []
            ? 'Nothing to remove: no key is older than ' . $age . 's.'
            : 'Removed ' . count($removed) . ' key(s): ' . implode(', ', $removed), 'ok');

        return self::SUCCESS;
    }
}
