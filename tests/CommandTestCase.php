<?php

declare(strict_types=1);

namespace Tests;

use Naf\Auth\Auth;
use Naf\Auth\Support\PasswordHasher;
use Naf\CLI\Core\AbstractCommand;
use Naf\CLI\Core\Input;
use Naf\CLI\Core\Output;
use Naf\Core\Config;
use Naf\OAuth\Server\Core\Authorization;
use Naf\OAuth\Server\Core\Claims;
use Naf\OAuth\Server\Core\ClientAuthenticator;
use Naf\OAuth\Server\Core\Discovery;
use Naf\OAuth\Server\Core\IdTokenIssuer;
use Naf\OAuth\Server\Core\ResourceServer;
use Naf\OAuth\Server\Core\ScopePolicy;
use Naf\OAuth\Server\Core\TokenEndpoint;
use Naf\OAuth\Server\Core\UserInfoEndpoint;
use Naf\OAuth\Server\Core\Users;
use Naf\OAuth\Server\Migrations\OAuthServerMigration;
use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Store\ClientStoreInterface;
use Naf\OAuth\Server\Store\KeyStoreInterface;
use Naf\OAuth\Server\Store\TokenStoreInterface;
use PDO;
use PHPUnit\Framework\TestCase;

use function Naf\app;

/**
 * Runs a command the way the console runs it.
 *
 * These commands are how a server is set up and how somebody decides whether it
 * works, so what they print is their behaviour, not a side effect of it. And the
 * mistakes they are prone to do not live in any class below them: naming a
 * command that does not exist, reading a setting from somewhere the application
 * does not, printing something that reads as reassuring when it is not. All of
 * those are invisible from a unit test and plain from here.
 *
 * Two things are supplied that a test may not have — a database in memory, and a
 * directory for keys that is not the repository. Nothing else is substituted.
 */
abstract class CommandTestCase extends TestCase
{
    /** Everything the plugin registers, cleared between tests so each boots fresh. */
    private const array SERVICES = [
        ClientStoreInterface::class, TokenStoreInterface::class, KeyStoreInterface::class,
        ScopePolicy::class, ClientAuthenticator::class, Authorization::class,
        Users::class, Claims::class, IdTokenIssuer::class, Discovery::class,
        UserInfoEndpoint::class, TokenEndpoint::class, ResourceServer::class,
        Config::class, PDO::class,
    ];

    /** Where signing keys go. Never the repository: oauth:keys:generate writes real files. */
    protected string $keyPath;

    protected function setUp(): void
    {
        if (!defined('BASE_PATH')) {
            define('BASE_PATH', dirname(__DIR__) . '/tests/Fixtures');
        }

        $this->keyPath = sys_get_temp_dir() . '/naf-oauth-server-cmd-' . bin2hex(random_bytes(6));

        $this->reset();
    }

    protected function tearDown(): void
    {
        $this->reset();

        foreach (glob($this->keyPath . '/*') ?: [] as $file) {
            @unlink($file);
        }

        @rmdir($this->keyPath);
    }

    // ------------------------------------------------------------- Building one

    /**
     * @param array<string, mixed> $server What goes under "oauth_server".
     * @param array<string, mixed>|null $auth What goes under "auth".
     */
    protected function configure(
        array $server = [],
        ?array $auth = null,
        ?string $publicUrl = 'https://id.example.test',
    ): void {
        app()->container()->set(Config::class, new Config([
            'public_url'   => $publicUrl,
            'oauth_server' => ['key_path' => $this->keyPath] + $server,
            'auth'         => $auth ?? ['session' => false, 'providers' => []],
        ]));
    }

    /** A database with the tables the plugin's own migration creates. */
    protected function database(bool $migrated = true): PDO
    {
        $connection = new PDO('sqlite::memory:');
        $connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        if ($migrated) {
            (new OAuthServerMigration())->up($connection);
        }

        app()->container()->set(PDO::class, $connection);

        return $connection;
    }

    protected function boot(): void
    {
        // The client store asks the container for the hasher naf/auth
        // registers, so that bootstrap has to have run. Both guard their
        // factories, so re-running is a no-op.
        require dirname(__DIR__) . '/vendor/naf/auth/bootstrap.php';
        require dirname(__DIR__) . '/bootstrap.php';
    }

    /**
     * A server that passes every check, so a test can break one thing and see it.
     *
     * That includes a registered client: a service nobody may ask is not a
     * working one, and the doctor is right to say so.
     *
     * @param array<string, mixed> $server Overrides on top of the healthy setup.
     */
    protected function healthy(array $server = [], bool $withClient = true): PDO
    {
        $connection = $this->database();

        // The real hasher's cost is a deliberate expense in production and a
        // pointless one here; these tests are about commands, not about cost.
        app()->container()->set(PasswordHasher::class, new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]));

        $this->configure($server + [
            'name'        => 'Probe ID',
            'login_route' => '/login',
            'scopes'      => ['posts.read' => ['label' => 'Read posts']],
        ]);

        $this->boot();

        if ($withClient) {
            $this->register();
        }

        return $connection;
    }

    /**
     * @param list<string> $grants
     * @return array{0: Client, 1: string|null}
     */
    protected function register(
        string $name = 'Acme Intranet',
        bool $confidential = true,
        array $grants = ['authorization_code', 'refresh_token'],
    ): array {
        return app()->container()->get(ClientStoreInterface::class)->register(
            name: $name,
            redirectUris: ['https://intranet.example.test/callback'],
            grants: $grants,
            scopes: ['posts.read'],
            confidential: $confidential,
        );
    }

    // ------------------------------------------------------------- Running one

    /**
     * @param list<string> $parameters Everything after the command name, as a shell passes it.
     */
    protected function execute(AbstractCommand $command, array $parameters = []): CommandResult
    {
        $input  = new Input($parameters, $command->getDefinition());
        $output = new Output();

        ob_start();

        try {
            $status = $command->run($input, $output);
        } finally {
            $printed = (string) ob_get_clean();
        }

        // Colour is for a terminal, not for an assertion.
        return new CommandResult($status, (string) preg_replace('/\x1b\[[0-9;]*m/', '', $printed));
    }

    protected function assertSucceeded(CommandResult $result): void
    {
        self::assertSame(0, $result->status, 'Expected a zero exit status. Printed:' . PHP_EOL . $result->output);
    }

    protected function assertFailed(CommandResult $result): void
    {
        self::assertNotSame(0, $result->status, 'Expected a non-zero exit status. Printed:' . PHP_EOL . $result->output);
    }

    private function reset(): void
    {
        $container = app()->container();

        foreach (self::SERVICES as $service) {
            $container->reset($service);
        }

        $container->reset(Auth::class);
        $container->reset(PasswordHasher::class);
    }
}
