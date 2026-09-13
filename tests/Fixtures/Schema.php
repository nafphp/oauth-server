<?php

declare(strict_types=1);

namespace Tests\Fixtures;

use NixPHP\Auth\Support\PasswordHasher;
use NixPHP\OAuth\Server\Migrations\OAuthServerMigration;
use NixPHP\OAuth\Server\Model\Client;
use NixPHP\OAuth\Server\Store\PdoClients;
use PDO;

/** A real database with the real schema, because that is where the guarantees live. */
final class Schema
{
    public static function connect(?string $file = null): PDO
    {
        $connection = new PDO('sqlite:' . ($file ?? ':memory:'));
        $connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $connection->exec('PRAGMA busy_timeout = 2000');

        return $connection;
    }

    public static function migrate(PDO $connection): PDO
    {
        (new OAuthServerMigration())->up($connection);

        return $connection;
    }

    /** A deliberately cheap hasher: these tests are about the protocol, not about cost. */
    public static function hasher(): PasswordHasher
    {
        return new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]);
    }

    public static function clients(PDO $connection): PdoClients
    {
        return new PdoClients($connection, self::hasher());
    }

    /**
     * @param list<string> $grants
     * @return array{0: Client, 1: string|null}
     */
    public static function register(
        PDO $connection,
        array $grants = ['authorization_code', 'refresh_token'],
        bool $confidential = true,
    ): array {
        return self::clients($connection)->register(
            name: 'Acme Intranet',
            redirectUris: ['https://intranet.example.test/callback'],
            grants: $grants,
            scopes: ['posts.read', 'posts.write'],
            confidential: $confidential,
        );
    }

    /** @param list<string> $grants */
    public static function client(
        PDO $connection,
        array $grants = ['authorization_code', 'refresh_token'],
        bool $confidential = true,
    ): Client {
        [$client] = self::register($connection, $grants, $confidential);

        return $client;
    }
}
