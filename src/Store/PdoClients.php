<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use InvalidArgumentException;
use Naf\Auth\Support\PasswordHasher;
use Naf\OAuth\Server\Model\Client;
use PDO;
use PDOStatement;
use RuntimeException;

/**
 * Client registrations in an existing PDO connection.
 *
 * Secrets are stored the way passwords are, through the very same hasher
 * naf/auth uses for people — so an application that raises its hashing cost
 * raises it here too, rather than having a second, quietly different policy for
 * machine credentials. The value handed to whoever registered the application is
 * the only copy that ever exists. Redirect URIs are kept one per line rather than comma-separated,
 * because a URI may contain a comma and must never be split by accident.
 */
final class PdoClients implements ClientStoreInterface
{
    public function __construct(
        private readonly PDO $connection,
        private readonly PasswordHasher $hasher,
    ) {
    }

    public function find(string $clientId): ?Client
    {
        $row = $this->execute(
            'SELECT * FROM oauth_clients WHERE client_id = :id AND revoked_at IS NULL',
            ['id' => $clientId],
        )->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? self::hydrate($row) : null;
    }

    public function register(
        string $name,
        array $redirectUris,
        array $grants,
        array $scopes,
        bool $confidential,
        array $audiences = [],
    ): array {
        if (trim($name) === '') {
            throw new InvalidArgumentException('A client needs a name.');
        }

        if ($redirectUris === [] && in_array('authorization_code', $grants, true)) {
            throw new InvalidArgumentException('A client using the authorization code grant needs a redirect URI.');
        }

        if (!$confidential && in_array('introspection', $grants, true)) {
            // A client id is not a secret — it travels in every authorize URL. A
            // public client that may introspect would let anyone who has ever seen
            // a login link ask about anybody's tokens.
            throw new InvalidArgumentException(
                'Introspection needs a client that can authenticate. Register it as confidential.',
            );
        }

        foreach ($redirectUris as $uri) {
            if (!str_starts_with($uri, 'https://') && !self::isLoopback($uri)) {
                throw new InvalidArgumentException(
                    'Redirect URIs must be https, or loopback for native applications: ' . $uri,
                );
            }
        }

        $clientId = bin2hex(random_bytes(16));
        $secret   = $confidential ? bin2hex(random_bytes(32)) : null;

        $this->execute(
            'INSERT INTO oauth_clients (client_id, name, secret_hash, redirect_uris, grants,'
            . ' scopes, audiences, created_at) VALUES (:id, :name, :secret, :uris, :grants, :scopes, :aud, :t)',
            [
                'id'     => $clientId,
                'name'   => trim($name),
                'secret' => $secret === null ? null : $this->hasher->hash($secret),
                'uris'   => implode("\n", $redirectUris),
                'grants' => implode(',', $grants),
                'scopes' => implode(',', $scopes),
                'aud'    => implode(',', $audiences),
                't'      => (string) time(),
            ],
        );

        $client = $this->find($clientId);

        if ($client === null) {
            throw new RuntimeException('The client could not be registered.');
        }

        return [$client, $secret];
    }

    public function rotateSecret(string $clientId, int $overlap): array
    {
        if ($overlap < 0) {
            throw new InvalidArgumentException('An overlap cannot be negative.');
        }

        $client = $this->find($clientId);

        if ($client === null) {
            throw new InvalidArgumentException('No such client: ' . $clientId);
        }

        if (!$client->isConfidential()) {
            throw new InvalidArgumentException(
                'This client is registered as public and has no secret to rotate. What protects its '
                . 'exchange is PKCE.',
            );
        }

        $secret = bin2hex(random_bytes(32));

        // One statement, so the secret being replaced and the moment it stops
        // being accepted are never briefly out of step with each other. The
        // overlap decides the SQL rather than being bound twice: a named
        // placeholder used more than once in one statement works only while PDO
        // emulates prepares, and emulation off is a common hardening setting.
        $this->execute(
            'UPDATE oauth_clients SET'
            . ' previous_secret_hash = ' . ($overlap > 0 ? 'secret_hash' : 'NULL') . ','
            . ' previous_secret_expires_at = :expires,'
            . ' secret_hash = :secret'
            . ' WHERE client_id = :id AND revoked_at IS NULL AND secret_hash IS NOT NULL',
            [
                'expires' => $overlap > 0 ? (string) (time() + $overlap) : null,
                'secret'  => $this->hasher->hash($secret),
                'id'      => $clientId,
            ],
        );

        $rotated = $this->find($clientId);

        // Read back and checked rather than trusted: "did that update match a
        // row?" has no portable answer, because MySQL counts rows it changed. A
        // client revoked in the meantime would otherwise be reported as rotated,
        // and somebody would deploy a secret that authenticates nothing.
        if ($rotated === null || !$this->hasher->verify($secret, $rotated->secretHash)) {
            throw new RuntimeException('The client secret could not be rotated.');
        }

        return [$rotated, $secret];
    }

    public function revoke(string $clientId): void
    {
        $this->execute(
            'UPDATE oauth_clients SET revoked_at = :t WHERE client_id = :id AND revoked_at IS NULL',
            ['t' => (string) time(), 'id' => $clientId],
        );
    }

    public function all(): array
    {
        $rows = $this->execute('SELECT * FROM oauth_clients WHERE revoked_at IS NULL ORDER BY created_at', [])
            ->fetchAll(PDO::FETCH_ASSOC);

        return array_map(self::hydrate(...), is_array($rows) ? $rows : []);
    }

    /** @param array<string, mixed> $row */
    private static function hydrate(array $row): Client
    {
        return new Client(
            id: (string) $row['client_id'],
            name: (string) $row['name'],
            secretHash: $row['secret_hash'] === null ? null : (string) $row['secret_hash'],
            redirectUris: self::split((string) $row['redirect_uris'], "\n"),
            grants: self::split((string) $row['grants'], ','),
            scopes: self::split((string) $row['scopes'], ','),
            audiences: self::split((string) $row['audiences'], ','),
            previousSecretHash: isset($row['previous_secret_hash']) ? (string) $row['previous_secret_hash'] : null,
            previousSecretExpiresAt: isset($row['previous_secret_expires_at'])
                ? (int) $row['previous_secret_expires_at']
                : null,
        );
    }

    /** @return list<string> */
    private static function split(string $value, string $separator): array
    {
        return array_values(array_filter(
            array_map(trim(...), explode($separator, $value)),
            static fn(string $item): bool => $item !== '',
        ));
    }

    private static function isLoopback(string $url): bool
    {
        return in_array(parse_url($url, PHP_URL_HOST), ['localhost', '127.0.0.1', '[::1]', '::1'], true);
    }

    /** @param array<string, string|null> $parameters */
    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->connection->prepare($sql);

        if ($statement === false || !$statement->execute($parameters)) {
            throw new RuntimeException('The client store could not be read or written.');
        }

        return $statement;
    }
}
