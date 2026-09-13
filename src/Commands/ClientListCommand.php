<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Commands;

use NixPHP\CLI\Core\{AbstractCommand, Input, Output};
use NixPHP\OAuth\Server\Store\ClientStoreInterface;
use function NixPHP\app;

/** Which applications may ask people to sign in with this server. */
class ClientListCommand extends AbstractCommand
{
    public const string NAME = 'oauth:client:list';

    protected function configure(): void
    {
        $this
            ->setTitle('List OAuth clients')
            ->setDescription('Show the registered applications, their kind and what they may ask for.');
    }

    public function run(Input $input, Output $output): int
    {
        $clients = app()->container()->get(ClientStoreInterface::class)->all();

        if ($clients === []) {
            $output->writeLine('No applications are registered yet.');

            return self::SUCCESS;
        }

        foreach ($clients as $client) {
            $output->writeEmptyLine();
            $output->writeLine('  ' . $client->name, 'ok');
            $output->writeLine('  ' . str_pad('Client ID', 16) . $client->id);
            $output->writeLine('  ' . str_pad('Kind', 16) . ($client->isConfidential() ? 'confidential' : 'public'));

            // A rotation is half-finished by definition: the new secret exists
            // here, and somebody still has to deploy it. Nothing runs when the
            // window lapses, so this is where it has to be visible — the doctor
            // says it too, but nobody runs the doctor to look up a client.
            if ($client->previousSecretIsLive()) {
                $output->writeLine(
                    '  ' . str_pad('Rotating', 16) . 'previous secret accepted until '
                    . date('Y-m-d H:i:s', (int) $client->previousSecretExpiresAt),
                    'warning',
                );
            }

            $output->writeLine('  ' . str_pad('Grants', 16) . (implode(', ', $client->grants) ?: '—'));
            $output->writeLine('  ' . str_pad('Scopes', 16) . (implode(', ', $client->scopes) ?: '—'));

            foreach ($client->redirectUris as $index => $uri) {
                $output->writeLine('  ' . str_pad($index === 0 ? 'Redirect URIs' : '', 16) . $uri);
            }
        }

        $output->writeEmptyLine();

        return self::SUCCESS;
    }
}
