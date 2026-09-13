<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Commands;

use Naf\CLI\Core\{AbstractCommand, Input, Output};
use Naf\OAuth\Server\Store\KeyStoreInterface;
use Throwable;
use function Naf\app;

/**
 * Put in place everything this server needs and cannot invent for itself.
 *
 * Only the signing key is actually created here, and only if there is none —
 * generating one during an ordinary web request is how two servers end up
 * signing with different keys and neither can check the other's tokens. The
 * schema belongs to the migrations, and registering a client is a decision.
 */
class SetupCommand extends AbstractCommand
{
    public const string NAME = 'oauth:server:setup';

    protected function configure(): void
    {
        $this
            ->setTitle('Set up the OAuth server')
            ->setDescription('Create the signing key if there is none, and say what is left to do.');
    }

    public function run(Input $input, Output $output): int
    {
        $keys = app()->container()->get(KeyStoreInterface::class);

        $output->writeEmptyLine();

        if ($keys->has()) {
            $output->writeLine('  Signing key already present — left alone.', 'ok');
        } else {
            try {
                $key = $keys->generate();
                $output->writeLine('  Signing key created: ' . $key->id, 'ok');
            } catch (Throwable $e) {
                $output->writeLine('  ' . $e->getMessage(), 'error');

                return self::ERROR;
            }
        }

        $output->writeEmptyLine();
        $output->writeLine('  Still to do:');
        $output->writeLine('    vendor/bin/naf db:migrate up              the OAuth schema, if you have not');
        $output->writeLine('    vendor/bin/naf oauth:client:create "…"    register an application');
        $output->writeLine('    vendor/bin/naf oauth:server:doctor        check the rest');
        $output->writeEmptyLine();

        return self::SUCCESS;
    }
}
