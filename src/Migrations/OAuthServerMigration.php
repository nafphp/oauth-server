<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Migrations;

use NixPHP\Database\Core\AbstractMigration;
use PDO;
use PDOException;

/**
 * Everything the authorization server stores.
 *
 * Unquoted lowercase identifiers and INT timestamps, so the same statements run
 * on MySQL, PostgreSQL and SQLite.
 *
 * Two conventions run through all of it:
 *
 * - **Nothing bearable is stored in the clear.** Codes and tokens are kept as
 *   SHA-256 hashes and client secrets as password hashes, so a copy of this
 *   database is not a set of working credentials.
 * - **The target API travels with the authorization.** Which API a token is for
 *   is decided once, when the person authorizes, and carried through every
 *   refresh. Re-deriving it from the client registration at each step would let a
 *   later change to that registration silently retarget tokens already granted.
 * - **A family is a row, not just a column.** Everything descended from one
 *   authorization shares a family id, and `oauth_families` is where its life
 *   ends. Issuing claims that row and revoking takes it, so the two cannot pass
 *   each other — which they otherwise do, and a replayed token then leaves a
 *   successor alive that the detection never saw.
 * - **A person is two columns, never one.** `user_provider` and `user_id` are
 *   the same pair nixphp/auth persists in a session, because account ids are
 *   only unique within their source. What the outside world sees instead is a
 *   subject from oauth_subjects, which reveals neither.
 */
class OAuthServerMigration extends AbstractMigration
{
    /** @var list<string> */
    private const array TABLES = [
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_clients
        (
            client_id     VARCHAR(64)  NOT NULL PRIMARY KEY,
            name          VARCHAR(190) NOT NULL,
            secret_hash   VARCHAR(255) NULL,

            -- The secret the current one replaced, and the moment it stops being
            -- accepted. Both null outside a rotation, which is most of the time.
            previous_secret_hash       VARCHAR(255) NULL,
            previous_secret_expires_at INT          NULL,
            redirect_uris TEXT         NOT NULL,
            grants        VARCHAR(255) NOT NULL,
            scopes        TEXT         NOT NULL,
            audiences     TEXT         NOT NULL,
            created_at    INT          NOT NULL,
            revoked_at    INT          NULL
        )
        SQL,
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_subjects
        (
            subject       VARCHAR(64)  NOT NULL PRIMARY KEY,
            user_provider VARCHAR(64)  NOT NULL,
            user_id       VARCHAR(190) NOT NULL,
            created_at    INT          NOT NULL
        )
        SQL,
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_requests
        (
            id             CHAR(64)     NOT NULL PRIMARY KEY,
            client_id      VARCHAR(64)  NOT NULL,
            redirect_uri   VARCHAR(500) NOT NULL,
            scope          TEXT         NOT NULL,
            state          VARCHAR(255) NOT NULL,
            code_challenge VARCHAR(128) NOT NULL,
            nonce          VARCHAR(255) NULL,
            audience       VARCHAR(190) NOT NULL,
            session_id     VARCHAR(190) NOT NULL,
            user_provider  VARCHAR(64)  NOT NULL,
            user_id        VARCHAR(190) NOT NULL,
            expires_at     INT          NOT NULL,
            consumed_at    INT          NULL
        )
        SQL,
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_families
        (
            family_id     CHAR(32)     NOT NULL PRIMARY KEY,
            client_id     VARCHAR(64)  NOT NULL,
            user_provider VARCHAR(64)  NOT NULL,
            user_id       VARCHAR(190) NOT NULL,
            uses          INT          NOT NULL,
            created_at    INT          NOT NULL,
            revoked_at    INT          NULL
        )
        SQL,
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_codes
        (
            code_hash      CHAR(64)     NOT NULL PRIMARY KEY,
            family_id      CHAR(32)     NOT NULL,
            client_id      VARCHAR(64)  NOT NULL,
            redirect_uri   VARCHAR(500) NOT NULL,
            scope          TEXT         NOT NULL,
            code_challenge VARCHAR(128) NOT NULL,
            nonce          VARCHAR(255) NULL,
            audience       VARCHAR(190) NOT NULL,
            user_provider  VARCHAR(64)  NOT NULL,
            user_id        VARCHAR(190) NOT NULL,
            expires_at     INT          NOT NULL,
            used_at        INT          NULL
        )
        SQL,
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_tokens
        (
            token_hash    CHAR(64)     NOT NULL PRIMARY KEY,
            family_id     CHAR(32)     NULL,
            client_id     VARCHAR(64)  NOT NULL,
            user_provider VARCHAR(64)  NULL,
            user_id       VARCHAR(190) NULL,
            scope         TEXT         NOT NULL,
            audience      VARCHAR(190) NOT NULL,
            expires_at    INT          NOT NULL,
            revoked_at    INT          NULL
        )
        SQL,
        <<<'SQL'
        CREATE TABLE IF NOT EXISTS oauth_refresh_tokens
        (
            token_hash        CHAR(64)     NOT NULL PRIMARY KEY,
            family_id         CHAR(32)     NOT NULL,
            successor_hash    CHAR(64)     NULL,
            access_token_hash CHAR(64)     NOT NULL,
            client_id         VARCHAR(64)  NOT NULL,
            user_provider     VARCHAR(64)  NOT NULL,
            user_id           VARCHAR(190) NOT NULL,
            scope             TEXT         NOT NULL,
            audience          VARCHAR(190) NOT NULL,
            expires_at        INT          NOT NULL,
            used_at           INT          NULL,
            revoked_at        INT          NULL
        )
        SQL,
    ];

    /** @var list<string> */
    private const array INDEXES = [
        'CREATE UNIQUE INDEX idx_oauth_subjects_account ON oauth_subjects (user_provider, user_id)',
        'CREATE INDEX idx_oauth_tokens_family ON oauth_tokens (family_id)',
        'CREATE INDEX idx_oauth_refresh_family ON oauth_refresh_tokens (family_id)',
        'CREATE INDEX idx_oauth_codes_expiry ON oauth_codes (expires_at)',
        'CREATE INDEX idx_oauth_requests_expiry ON oauth_requests (expires_at)',
    ];

    /**
     * Identifier columns that must stay case-sensitive.
     *
     * These hold base64url values, where "aB" and "Ab" are different identifiers.
     * MySQL's default collation is case-insensitive, so without this a token or a
     * subject presented with its case mangled still matches the stored one, and
     * two distinct values collide on insert.
     *
     * @var list<array{0:string,1:string,2:int}>
     */
    private const array EXACT = [
        ['oauth_subjects', 'subject', 64],
        ['oauth_requests', 'id', 64],
        ['oauth_families', 'family_id', 32],
        ['oauth_codes', 'family_id', 32],
        ['oauth_tokens', 'family_id', 32],
        ['oauth_refresh_tokens', 'family_id', 32],
    ];

    public function up(PDO $connection): void
    {
        foreach (self::TABLES as $sql) {
            $connection->exec($sql);
        }

        if ($connection->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql') {
            foreach (self::EXACT as [$table, $column, $length]) {
                $connection->exec(
                    'ALTER TABLE ' . $table . ' MODIFY ' . $column
                    . ' VARCHAR(' . $length . ') COLLATE utf8mb4_bin NOT NULL'
                );
            }
        }

        foreach (self::INDEXES as $sql) {
            $this->createIndex($connection, $sql);
        }
    }

    public function down(PDO $connection): void
    {
        foreach (['oauth_refresh_tokens', 'oauth_tokens', 'oauth_codes', 'oauth_families',
                  'oauth_requests', 'oauth_subjects', 'oauth_clients'] as $table) {
            $connection->exec('DROP TABLE IF EXISTS ' . $table);
        }
    }

    private function createIndex(PDO $connection, string $sql): void
    {
        try {
            $connection->exec($sql);
        } catch (PDOException $exception) {
            // Already there. MySQL says 1061, SQLite and PostgreSQL say so in words.
            if ($exception->getCode() !== '42000'
                && !str_contains(strtolower($exception->getMessage()), 'already exists')) {
                throw $exception;
            }
        }
    }
}
