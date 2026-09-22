<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Commands;

use Naf\CLI\Core\AbstractCommand;
use Naf\CLI\Core\Input;
use Naf\CLI\Core\Output;
use Naf\Core\Route;
use Naf\OAuth\Server\Core\ScopePolicy;
use Naf\OAuth\Server\Store\ClientStoreInterface;
use Naf\OAuth\Server\Store\KeyStoreInterface;
use PDO;
use Throwable;

use function Naf\app;
use function Naf\config;

/**
 * What has to be true before this server can answer anybody.
 *
 * The alternative is finding out mid-redirect, in front of a person who cannot
 * act on it. Nothing here prints a secret: whether one is configured is worth
 * knowing, what it is, is not.
 */
class DoctorCommand extends AbstractCommand
{
    public const string NAME = 'oauth:server:doctor';

    private int $problems = 0;

    protected function configure(): void
    {
        $this
            ->setTitle('Check the OAuth server setup')
            ->setDescription('Verify the issuer, connection, schema, keys, scopes, login route and clients.');
    }

    public function run(Input $input, Output $output): int
    {
        $output->writeEmptyLine();

        $this->identity($output);
        $this->schema($output);
        $this->keys($output);
        $this->scopes($output);
        $this->login($output);

        $output->writeEmptyLine();
        $output->writeLine(
            $this->problems === 0
            ? '  Ready to answer.'
            : '  ' . $this->problems . ' thing(s) to fix.',
            $this->problems === 0 ? 'ok' : 'error',
        );
        $output->writeEmptyLine();

        return $this->problems === 0 ? self::SUCCESS : self::ERROR;
    }

    private function identity(Output $output): void
    {
        $url  = config('public_url');
        $name = config('oauth_server:name');

        $this->line(
            $output,
            'issuer (public_url)',
            is_string($url) && trim($url) !== '' ? $url : 'MISSING — relying parties check this value',
            is_string($url) && trim($url) !== '',
        );

        $this->line(
            $output,
            'service name',
            is_string($name) && trim($name) !== '' ? $name : 'MISSING — the consent screen has nothing to call you',
            is_string($name) && trim($name) !== '',
        );
    }

    private function schema(Output $output): void
    {
        try {
            $connection = app()->container()->get(PDO::class);
        } catch (Throwable $e) {
            $this->line($output, 'connection', $e->getMessage(), false);

            return;
        }

        $this->line($output, 'connection', $connection->getAttribute(PDO::ATTR_DRIVER_NAME), true);

        foreach (['oauth_clients', 'oauth_families', 'oauth_codes', 'oauth_tokens',
            'oauth_refresh_tokens', 'oauth_requests', 'oauth_subjects'] as $table) {
            try {
                $connection->query('SELECT 1 FROM ' . $table . ' WHERE 1 = 0');
                $present = true;
            } catch (Throwable) {
                $present = false;
            }

            if (!$present) {
                $this->line($output, $table, 'missing — run "naf db:migrate up"', false);
            }
        }

        if ($this->problems === 0) {
            $this->line($output, 'schema', 'all tables present', true);
        }

        try {
            $clients = app()->container()->get(ClientStoreInterface::class)->all();
            $count   = count($clients);

            $this->line($output, 'registered clients', $count === 0
                ? 'none — run "naf oauth:client:create"'
                : (string) $count, $count > 0);

            // Not a fault — a rotation in progress is exactly what it should look
            // like. It is reported because it is a deadline somebody set and
            // nothing else will remind them of: when it lapses, a client that was
            // never redeployed stops authenticating.
            foreach ($clients as $client) {
                if ($client->previousSecretIsLive()) {
                    $this->line(
                        $output,
                        '  ' . $client->name,
                        'previous secret accepted until '
                        . date('Y-m-d H:i:s', (int) $client->previousSecretExpiresAt),
                        true,
                    );
                }
            }
        } catch (Throwable $e) {
            $this->line($output, 'registered clients', $e->getMessage(), false);
        }
    }

    private function keys(Output $output): void
    {
        try {
            $keys = app()->container()->get(KeyStoreInterface::class);
        } catch (Throwable $e) {
            $this->line($output, 'signing keys', $e->getMessage(), false);

            return;
        }

        if (!$keys->has()) {
            // Not a fault: an OAuth2 server is a complete thing to be.
            $output->writeLine('  - ' . str_pad('OpenID Connect', 22) . 'off — no signing key. Run "naf oauth:server:setup" to enable it.');

            return;
        }

        $this->line($output, 'OpenID Connect', 'on, ' . count($keys->all()) . ' published key(s)', true);
    }

    private function scopes(Output $output): void
    {
        $names = app()->container()->get(ScopePolicy::class)->names();

        // Only openid, profile and email means no API scopes, which is fine for a
        // server that only signs people in.
        $this->line($output, 'scopes', implode(', ', $names), true);
    }

    private function login(Output $output): void
    {
        $configured = config('oauth_server:login_route');

        if (is_string($configured) && $configured !== '') {
            $this->line($output, 'login route', $configured, true);

            return;
        }

        $routes = app()->container()->get(Route::class)->all();

        $this->line(
            $output,
            'login route',
            isset($routes['login'])
            ? (string) $routes['login']['path'] . ' (derived from the route named "login")'
            : 'MISSING — no route named "login", so set oauth_server:login_route',
            isset($routes['login']),
        );
    }

    private function line(Output $output, string $label, string $value, bool $good): void
    {
        if (!$good) {
            $this->problems++;
        }

        $output->writeLine('  ' . ($good ? '+' : '!') . ' ' . str_pad($label, 22) . $value, $good ? null : 'error');
    }
}
