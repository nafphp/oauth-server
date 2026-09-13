<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Commands;

use Naf\CLI\Core\{AbstractCommand, Input, Output};
use Naf\OAuth\Server\Store\KeyStoreInterface;
use Throwable;
use function Naf\app;

/**
 * Create the key this server signs ID tokens with — or rotate to a new one.
 *
 * Run once at setup, and again whenever a key should be replaced. Rotating does
 * not invalidate anything: the new key signs from now on, the old one stays
 * published so tokens already out there keep verifying, and removing it later is
 * a separate decision made with oauth:keys:prune.
 */
class KeysGenerateCommand extends AbstractCommand
{
    public const string NAME = 'oauth:keys:generate';

    protected function configure(): void
    {
        $this
            ->setTitle('Generate an ID token signing key')
            ->setDescription('Create the signing key, or rotate to a new one. Old keys stay published.');
    }

    public function run(Input $input, Output $output): int
    {
        $keys     = app()->container()->get(KeyStoreInterface::class);
        $rotating = $keys->has();

        try {
            $key = $keys->generate();
        } catch (Throwable $e) {
            $output->writeLine($e->getMessage(), 'error');

            return self::ERROR;
        }

        $output->writeEmptyLine();
        $output->writeLine('  ' . ($rotating ? 'Rotated to a new signing key.' : 'Signing key created.'), 'ok');
        $output->writeLine('  ' . str_pad('Key ID', 16) . $key->id);
        $output->writeLine('  ' . str_pad('Published keys', 16) . (string) count($keys->all()));
        $output->writeEmptyLine();

        if ($rotating) {
            $output->writeLine('  The previous key stays published so tokens signed with it still verify.');
            $output->writeLine('  Remove it with "naf oauth:keys:prune" once those tokens have expired.');
            $output->writeEmptyLine();
        }

        return self::SUCCESS;
    }
}
