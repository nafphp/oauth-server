<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Commands;

use InvalidArgumentException;
use NixPHP\CLI\Core\{AbstractCommand, Input, Output};
use NixPHP\OAuth\Server\Store\ClientStoreInterface;
use function NixPHP\app;

/**
 * Register an application.
 *
 * Registrations are administrative data, so they are made one at a time and kept
 * in the database — not accumulated in a configuration file that gets deployed.
 * The secret is printed once, because after this it exists only as a hash.
 */
class ClientCreateCommand extends AbstractCommand
{
    public const string NAME = 'oauth:client:create';

    protected function configure(): void
    {
        $this
            ->setTitle('Register an OAuth client')
            ->setDescription('Register an application that may ask people to sign in with this server.')
            ->addArgument('name')
            ->addOption('redirect', 'r', expectsValue: true)
            ->addOption('scope', 's', expectsValue: true)
            ->addOption('grant', 'g', expectsValue: true)
            ->addOption('public', 'p');
    }

    public function run(Input $input, Output $output): int
    {
        $name = $input->getArgument('name');

        if ($name === null || trim($name) === '') {
            $output->writeLine('Give the application a name: nix ' . self::NAME . ' "Acme Intranet" --redirect=…', 'error');

            return self::ERROR;
        }

        $public = $input->getOption('public') !== null;

        try {
            [$client, $secret] = app()->container()->get(ClientStoreInterface::class)->register(
                name: $name,
                redirectUris: self::values($input, 'redirect'),
                grants: self::values($input, 'grant') ?: ['authorization_code', 'refresh_token'],
                scopes: self::values($input, 'scope'),
                confidential: !$public,
            );
        } catch (InvalidArgumentException $e) {
            $output->writeLine($e->getMessage(), 'error');

            return self::ERROR;
        }

        $output->writeEmptyLine();
        $output->writeLine('  ' . $client->name, 'ok');
        $output->writeLine('  ' . str_pad('Client ID', 16) . $client->id);

        if ($secret !== null) {
            $output->writeLine('  ' . str_pad('Client secret', 16) . $secret);
            $output->writeEmptyLine();
            $output->writeLine('  Copy the secret now. It is stored only as a hash and cannot be shown again.');
        } else {
            $output->writeEmptyLine();
            $output->writeLine('  A public client: no secret, and PKCE is what protects its exchange.');
        }

        $output->writeEmptyLine();

        return self::SUCCESS;
    }

    /**
     * An option may be given more than once, in which case it arrives as a list;
     * a single one may also carry several values separated by commas.
     *
     * @return list<string>
     */
    private static function values(Input $input, string $option): array
    {
        $value = $input->getOption($option);

        if ($value === null || is_bool($value)) {
            return [];
        }

        $items = [];

        foreach (is_array($value) ? $value : [$value] as $entry) {
            foreach (explode(',', (string) $entry) as $item) {
                if (trim($item) !== '') {
                    $items[] = trim($item);
                }
            }
        }

        return array_values(array_unique($items));
    }
}
