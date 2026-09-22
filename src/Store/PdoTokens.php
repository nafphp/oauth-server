<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\AuthorizationRequest;
use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Model\IssuedTokens;
use Naf\OAuth\Server\Model\TokenRecord;
use PDO;
use PDOStatement;
use RuntimeException;
use SensitiveParameter;
use Throwable;

/**
 * The issuing side of the server, in one PDO connection.
 *
 * Every placeholder appears once per statement, even where that means binding
 * the same value twice under two names. A named parameter reused within one
 * statement works only while PDO emulates prepares; with native prepares — a
 * common hardening setting — it is an error, and the whole server stops working.
 *
 * Two rules shape every method here.
 *
 * **Nothing bearable is stored in the clear.** Codes and tokens go in as SHA-256
 * hashes, so a copy of this database is a list of fingerprints rather than a set
 * of working credentials.
 *
 * **A claim is one statement.** Redeeming a code or a refresh token begins with a
 * single conditional UPDATE. The row it matches is locked until the transaction
 * ends, so a second request for the same code blocks, then finds it spent — no
 * read-then-write window for two requests to slip through. Issuing the tokens
 * happens inside that same transaction, because a code that is spent without
 * tokens to show for it is worse than one that can be tried again.
 *
 * Which failures keep the claim, and which give it back, is a deliberate split:
 *
 * - a **credential or binding mismatch** commits the claim. A code presented with
 *   the wrong client, redirect URI or PKCE verifier is evidence that it has
 *   leaked, and going on accepting it would be the worse outcome.
 * - a **failure on our side** rolls back. Nothing was issued, so nothing was
 *   spent, and the client may try again.
 *
 * Rotation is strict: there is no window in which a spent refresh token still
 * answers. Implementing one honestly would mean either keeping a bearer token in
 * plaintext to hand out twice, or standing down replay detection for its
 * duration — a quiet weakening of the one thing rotation exists to do. Clients
 * that might refresh twice at once should serialise their own refreshes.
 */
final class PdoTokens implements TokenStoreInterface
{
    public function __construct(private readonly PDO $connection)
    {
    }

    // ------------------------------------------------------------- Subjects

    public function subjectFor(string $userProvider, string $userId): string
    {
        $existing = $this->one(
            'SELECT subject FROM oauth_subjects WHERE user_provider = :p AND user_id = :u',
            ['p' => $userProvider, 'u' => $userId],
        );

        if (is_array($existing)) {
            return (string) $existing['subject'];
        }

        // Random, never derived from anything that can change. A provider can be
        // renamed and an account can be moved without the outside world noticing.
        $subject = self::token(16);

        try {
            $this->execute(
                'INSERT INTO oauth_subjects (subject, user_provider, user_id, created_at)'
                . ' VALUES (:s, :p, :u, :t)',
                ['s' => $subject, 'p' => $userProvider, 'u' => $userId, 't' => (string) time()],
            );
        } catch (Throwable) {
            // Somebody created it in between; theirs is as good as ours.
            $row = $this->one(
                'SELECT subject FROM oauth_subjects WHERE user_provider = :p AND user_id = :u',
                ['p' => $userProvider, 'u' => $userId],
            );

            if (!is_array($row)) {
                throw new RuntimeException('Could not assign a subject.');
            }

            return (string) $row['subject'];
        }

        return $subject;
    }

    // ------------------------------------------------- Requests and consent

    public function storeRequest(AuthorizationRequest $request, int $ttl): string
    {
        $id = self::token(32);

        $this->execute(
            'INSERT INTO oauth_requests (id, client_id, redirect_uri, scope, state, code_challenge,'
            . ' nonce, audience, session_id, user_provider, user_id, expires_at)'
            . ' VALUES (:id, :client, :uri, :scope, :state, :challenge, :nonce, :aud, :session, :p, :u, :exp)',
            [
                'id'        => $id,
                'client'    => $request->clientId,
                'uri'       => $request->redirectUri,
                'scope'     => $request->scope(),
                'state'     => $request->state,
                'challenge' => $request->codeChallenge,
                'nonce'     => $request->nonce,
                'aud'       => $request->audience,
                'session'   => $request->sessionId,
                'p'         => $request->userProvider,
                'u'         => $request->userId,
                'exp'       => (string) (time() + $ttl),
            ],
        );

        return $id;
    }

    public function consumeRequest(string $id, string $sessionId, string $userProvider, string $userId): AuthorizationRequest
    {
        $now = time();

        // Consent is for the request the server validated, given by the person who
        // was asked, in the browser they were asked in. All three are conditions of
        // the claim rather than checks afterwards.
        $claimed = $this->execute(
            'UPDATE oauth_requests SET consumed_at = :now'
            . ' WHERE id = :id AND consumed_at IS NULL AND expires_at > :deadline'
            . ' AND session_id = :session AND user_provider = :p AND user_id = :u',
            [
                'now'      => (string) $now,
                'deadline' => (string) $now,
                'id'       => $id,
                'session'  => $sessionId,
                'p'        => $userProvider,
                'u'        => $userId,
            ],
        )->rowCount();

        $row = $this->one('SELECT * FROM oauth_requests WHERE id = :id', ['id' => $id]);

        if ($claimed !== 1 || !is_array($row)) {
            throw OAuthError::refuse(
                'invalid_request',
                'That authorization request is no longer open. It expired, it was already answered, or it belongs to another sign-in.',
            );
        }

        return self::requestFrom($row);
    }

    // ------------------------------------------------------------ Codes

    public function issueCode(AuthorizationRequest $request, int $ttl): string
    {
        $code   = self::token(32);
        $family = self::token(8);

        // Everything this code goes on to produce belongs to this family, and this
        // row is where its life ends. Issuing claims it, revoking takes it — see
        // claimFamily().
        $this->execute(
            'INSERT INTO oauth_families (family_id, client_id, user_provider, user_id, uses, created_at)'
            . ' VALUES (:f, :client, :p, :u, 0, :t)',
            [
                'f'      => $family,
                'client' => $request->clientId,
                'p'      => $request->userProvider,
                'u'      => $request->userId,
                't'      => (string) time(),
            ],
        );

        $this->execute(
            'INSERT INTO oauth_codes (code_hash, family_id, client_id, redirect_uri, scope,'
            . ' code_challenge, nonce, audience, user_provider, user_id, expires_at)'
            . ' VALUES (:hash, :family, :client, :uri, :scope, :challenge, :nonce, :aud, :p, :u, :exp)',
            [
                'hash'      => self::hash($code),
                'family'    => $family,
                'client'    => $request->clientId,
                'uri'       => $request->redirectUri,
                'scope'     => $request->scope(),
                'challenge' => $request->codeChallenge,
                'nonce'     => $request->nonce,
                'aud'       => $request->audience,
                'p'         => $request->userProvider,
                'u'         => $request->userId,
                'exp'       => (string) (time() + $ttl),
            ],
        );

        return $code;
    }

    public function redeem(
        #[SensitiveParameter]
        string $code,
        Client $client,
        ?string $redirectUri,
        #[SensitiveParameter]
        string $verifier,
        int $accessTtl,
        int $refreshTtl,
    ): IssuedTokens {
        $hash = self::hash($code);
        $now  = time();

        // Read outside the transaction, on purpose: see claimFamily().
        $family = $this->one('SELECT family_id FROM oauth_codes WHERE code_hash = :hash', ['hash' => $hash]);

        if (!is_array($family)) {
            throw OAuthError::refuse('invalid_grant', 'That authorization code is not usable.');
        }

        $this->connection->beginTransaction();

        try {
            if (!$this->claimFamily((string) $family['family_id'])) {
                $this->connection->rollBack();

                throw OAuthError::refuse('invalid_grant', 'That authorization has been withdrawn.');
            }

            /** @var array<string, mixed> $row */
            $row = $this->one('SELECT * FROM oauth_codes WHERE code_hash = :hash', ['hash' => $hash]);

            $claimed = $this->execute(
                'UPDATE oauth_codes SET used_at = :now'
                . ' WHERE code_hash = :hash AND used_at IS NULL AND expires_at > :deadline',
                ['now' => (string) $now, 'deadline' => (string) $now, 'hash' => $hash],
            )->rowCount();

            if ($claimed !== 1) {
                $spent = $this->one(
                    'SELECT used_at FROM oauth_codes WHERE code_hash = :hash',
                    ['hash' => $hash],
                );

                if (is_array($spent) && $spent['used_at'] !== null) {
                    // Presented twice. Whatever the first use produced is no longer
                    // trustworthy either, so the whole family goes — committed here
                    // rather than in a transaction of its own.
                    $this->revokeFamily((string) $row['family_id']);
                    $this->connection->commit();
                } else {
                    $this->connection->rollBack();
                }

                throw OAuthError::refuse('invalid_grant', 'That authorization code is not usable.');
            }

            $mismatch = !hash_equals((string) $row['client_id'], $client->id)
                || !hash_equals((string) $row['code_challenge'], self::challenge($verifier))
                || ($redirectUri !== null && !hash_equals((string) $row['redirect_uri'], $redirectUri));

            if ($mismatch) {
                // The claim stands: a code offered with the wrong credentials has
                // been somewhere it should not have been.
                $this->connection->commit();

                throw OAuthError::refuse('invalid_grant', 'That authorization code is not usable.');
            }

            $tokens = $this->issue(
                clientId: $client->id,
                familyId: (string) $row['family_id'],
                userProvider: (string) $row['user_provider'],
                userId: (string) $row['user_id'],
                scope: (string) $row['scope'],

                // What the person authorized, not what the registration says today.
                audience: (string) $row['audience'],
                accessTtl: $accessTtl,
                refreshTtl: $client->allows('refresh_token') ? $refreshTtl : null,
            );

            $this->connection->commit();

            // The nonce belongs to the login this code came from, and only to it:
            // OpenID Connect §12.2 forbids repeating it on a refresh, which is why
            // it travels no further than here.
            return $row['nonce'] === null ? $tokens : new IssuedTokens(
                accessToken: $tokens->accessToken,
                expiresIn: $tokens->expiresIn,
                scope: $tokens->scope,
                refreshToken: $tokens->refreshToken,
                userProvider: $tokens->userProvider,
                userId: $tokens->userId,
                nonce: (string) $row['nonce'],
            );
        } catch (Throwable $e) {
            // Whatever went wrong, this transaction ends here. The paths that mean
            // to keep the claim have already committed, so this is a no-op for
            // them — and every other path, including a protocol refusal raised
            // mid-transaction, gives the code back rather than spending it on an
            // exchange that produced nothing.
            if ($this->connection->inTransaction()) {
                $this->connection->rollBack();
            }

            throw $e;
        }
    }

    // ---------------------------------------------------------- Refreshing

    /** @param list<string>|null $scopes */
    public function rotate(
        #[SensitiveParameter]
        string $refreshToken,
        Client $client,
        int $accessTtl,
        int $refreshTtl,
        ?array $scopes = null,
    ): IssuedTokens {
        $hash = self::hash($refreshToken);
        $now  = time();

        // Read outside the transaction, on purpose: see claimFamily().
        $family = $this->one('SELECT family_id FROM oauth_refresh_tokens WHERE token_hash = :hash', ['hash' => $hash]);

        if (!is_array($family)) {
            throw OAuthError::refuse('invalid_grant', 'That refresh token is not usable.');
        }

        $this->connection->beginTransaction();

        try {
            if (!$this->claimFamily((string) $family['family_id'])) {
                $this->connection->rollBack();

                throw OAuthError::refuse('invalid_grant', 'That authorization has been withdrawn.');
            }

            /** @var array<string, mixed> $row */
            $row = $this->one('SELECT * FROM oauth_refresh_tokens WHERE token_hash = :hash', ['hash' => $hash]);

            $claimed = $this->execute(
                'UPDATE oauth_refresh_tokens SET used_at = :now'
                . ' WHERE token_hash = :hash AND used_at IS NULL AND revoked_at IS NULL AND expires_at > :deadline',
                ['now' => (string) $now, 'deadline' => (string) $now, 'hash' => $hash],
            )->rowCount();

            if ($claimed !== 1) {
                // Holding the family makes this the authoritative answer: nobody
                // else can be spending or revoking anything in it underneath us.
                $spent = $this->one(
                    'SELECT used_at FROM oauth_refresh_tokens WHERE token_hash = :hash',
                    ['hash' => $hash],
                );

                if (is_array($spent) && $spent['used_at'] !== null) {
                    // A spent refresh token coming back means somebody has a copy.
                    // Everything descended from that authorization stops here, in
                    // this transaction, so the revocation commits with the claim
                    // rather than as a separate act that can fail on its own.
                    $this->revokeFamily((string) $row['family_id']);
                    $this->connection->commit();
                } else {
                    $this->connection->rollBack();
                }

                throw OAuthError::refuse('invalid_grant', 'That refresh token is not usable.');
            }

            if (!hash_equals((string) $row['client_id'], $client->id)) {
                $this->connection->commit();

                throw OAuthError::refuse('invalid_grant', 'That refresh token is not usable.');
            }

            // The access token it came with dies with it, so a rotation cannot leave
            // two live tokens behind.
            $this->execute(
                'UPDATE oauth_tokens SET revoked_at = :now WHERE token_hash = :hash AND revoked_at IS NULL',
                ['now' => (string) $now, 'hash' => (string) $row['access_token_hash']],
            );

            $tokens = $this->issue(
                clientId: $client->id,
                familyId: (string) $row['family_id'],
                userProvider: (string) $row['user_provider'],
                userId: (string) $row['user_id'],
                scope: self::narrow((string) $row['scope'], $scopes),

                // The chain keeps the target it was granted for. Re-deriving it
                // would let a changed registration retarget an existing grant.
                audience: (string) $row['audience'],
                accessTtl: $accessTtl,
                refreshTtl: $refreshTtl,
                predecessor: $hash,
            );

            $this->connection->commit();

            return $tokens;
        } catch (Throwable $e) {
            // As in redeem(): the deliberate paths have already committed, and
            // anything else — a refused scope, a withdrawn family — leaves nothing
            // half-open behind it.
            if ($this->connection->inTransaction()) {
                $this->connection->rollBack();
            }

            throw $e;
        }
    }

    // ------------------------------------------------------ Client credentials

    /** @param list<string> $scopes */
    public function issueForClient(Client $client, array $scopes, string $audience, int $accessTtl): IssuedTokens
    {
        // No person, so no refresh token either: the client can always ask again
        // with the credentials it already has.
        return $this->issue(
            clientId: $client->id,
            familyId: null,
            userProvider: null,
            userId: null,
            scope: implode(' ', $scopes),
            audience: $audience,
            accessTtl: $accessTtl,
            refreshTtl: null,
        );
    }

    // ------------------------------------------------------------ Using them

    public function inspect(#[SensitiveParameter] string $accessToken): ?TokenRecord
    {
        // Joined against the registration: withdrawing a client has to take its
        // tokens with it, or revoking one means nothing until they expire.
        $row = $this->one(
            'SELECT t.* FROM oauth_tokens t'
            . ' INNER JOIN oauth_clients c ON c.client_id = t.client_id AND c.revoked_at IS NULL'
            . ' WHERE t.token_hash = :hash AND t.revoked_at IS NULL AND t.expires_at > :now',
            ['hash' => self::hash($accessToken), 'now' => (string) time()],
        );

        if (!is_array($row)) {
            return null;
        }

        return new TokenRecord(
            clientId: (string) $row['client_id'],
            userProvider: $row['user_provider'] === null ? null : (string) $row['user_provider'],
            userId: $row['user_id'] === null ? null : (string) $row['user_id'],
            scopes: self::scopes((string) $row['scope']),
            audience: (string) $row['audience'],
            expiresAt: (int) $row['expires_at'],
        );
    }

    public function revoke(#[SensitiveParameter] string $token, Client $client): void
    {
        $hash = self::hash($token);
        $now  = (string) time();

        // RFC 7009: a client may hand back either kind, and revoking a refresh
        // token takes the authorization with it.
        $refresh = $this->one(
            'SELECT family_id, client_id FROM oauth_refresh_tokens WHERE token_hash = :hash',
            ['hash' => $hash],
        );

        if (is_array($refresh)) {
            if (hash_equals((string) $refresh['client_id'], $client->id)) {
                $this->revokeFamily((string) $refresh['family_id']);
            }

            return;
        }

        $this->execute(
            'UPDATE oauth_tokens SET revoked_at = :now'
            . ' WHERE token_hash = :hash AND client_id = :client AND revoked_at IS NULL',
            ['now' => $now, 'hash' => $hash, 'client' => $client->id],
        );
    }

    /**
     * End everything that came from one authorization. Idempotent.
     *
     * The family row is taken first, and the whole thing is one transaction. That
     * ordering is the point: a rotation that is issuing right now holds that same
     * row, so this waits for it and then revokes what it produced. Without it the
     * two pass each other — the replay is detected, the revocation sweeps the rows
     * it can see, and a successor committed a millisecond later survives the very
     * detection that was supposed to end the chain.
     */
    public function revokeFamily(string $familyId): void
    {
        $now   = (string) time();
        $owned = !$this->connection->inTransaction();

        if ($owned) {
            $this->connection->beginTransaction();
        }

        try {
            $this->execute(
                'UPDATE oauth_families SET revoked_at = :now WHERE family_id = :f AND revoked_at IS NULL',
                ['now' => $now, 'f' => $familyId],
            );

            foreach (['oauth_tokens', 'oauth_refresh_tokens'] as $table) {
                $this->execute(
                    'UPDATE ' . $table . ' SET revoked_at = :now WHERE family_id = :f AND revoked_at IS NULL',
                    ['now' => $now, 'f' => $familyId],
                );
            }

            if ($owned) {
                $this->connection->commit();
            }
        } catch (Throwable $e) {
            if ($owned && $this->connection->inTransaction()) {
                $this->connection->rollBack();
            }

            throw $e;
        }
    }

    /**
     * Take the family that owns this code or refresh token, for the rest of the
     * transaction. Must be the first statement in it.
     *
     * Two rules, and both of them were learned the hard way.
     *
     * **The family first.** Every path through a family — redeeming, rotating,
     * revoking — takes this row before it takes any token row. revokeFamily()
     * does the same. Two transactions that approach the same pair from opposite
     * ends deadlock, PostgreSQL aborts one of them, and an aborted revocation is
     * a replay that was noticed and then not acted on: the family it should have
     * ended stays alive, and so does the successor being issued alongside it.
     *
     * **As a write, with nothing read inside the transaction before it.** The
     * family id is looked up before the transaction opens, where it needs no
     * lock: a row's family never changes. A transaction that reads first and
     * writes second holds a read lock it later has to upgrade, and two SQLite
     * connections doing that at once fail outright rather than queue — the same
     * swallowed revocation, arrived at from the other direction. Naming the id
     * outright also keeps the statement free of a subquery, which MySQL would
     * lock the read rows for under REPEATABLE READ, deadlocking this against the
     * very token row the caller is about to claim.
     *
     * It counts the use rather than writing something back unchanged, because
     * MySQL reports rows it actually changed: an update that sets a column to the
     * value it already holds affects nothing, and the claim would read as a
     * refusal. Incrementing always changes something, on every driver.
     *
     * @return bool False when the family is already revoked.
     */
    private function claimFamily(string $familyId): bool
    {
        return $this->execute(
            'UPDATE oauth_families SET uses = uses + 1 WHERE family_id = :f AND revoked_at IS NULL',
            ['f' => $familyId],
        )->rowCount() === 1;
    }

    // ---------------------------------------------------------------- Internals

    private function issue(
        string $clientId,
        ?string $familyId,
        ?string $userProvider,
        ?string $userId,
        string $scope,
        string $audience,
        int $accessTtl,
        ?int $refreshTtl,
        ?string $predecessor = null,
    ): IssuedTokens {
        $access     = self::token(32);
        $accessHash = self::hash($access);
        $now        = time();

        $this->execute(
            'INSERT INTO oauth_tokens (token_hash, family_id, client_id, user_provider, user_id,'
            . ' scope, audience, expires_at) VALUES (:hash, :family, :client, :p, :u, :scope, :aud, :exp)',
            [
                'hash'   => $accessHash,
                'family' => $familyId,
                'client' => $clientId,
                'p'      => $userProvider,
                'u'      => $userId,
                'scope'  => $scope,
                'aud'    => $audience,
                'exp'    => (string) ($now + $accessTtl),
            ],
        );

        $refresh = null;

        if ($refreshTtl !== null && $familyId !== null && $userProvider !== null && $userId !== null) {
            $refresh     = self::token(32);
            $refreshHash = self::hash($refresh);

            $this->execute(
                'INSERT INTO oauth_refresh_tokens (token_hash, family_id, access_token_hash, client_id,'
                . ' user_provider, user_id, scope, audience, expires_at)'
                . ' VALUES (:hash, :family, :access, :client, :p, :u, :scope, :aud, :exp)',
                [
                    'hash'   => $refreshHash,
                    'family' => $familyId,
                    'access' => $accessHash,
                    'client' => $clientId,
                    'p'      => $userProvider,
                    'u'      => $userId,
                    'scope'  => $scope,
                    'aud'    => $audience,
                    'exp'    => (string) ($now + $refreshTtl),
                ],
            );

            if ($predecessor !== null) {
                $this->execute(
                    'UPDATE oauth_refresh_tokens SET successor_hash = :s WHERE token_hash = :hash',
                    ['s' => $refreshHash, 'hash' => $predecessor],
                );
            }
        }

        return new IssuedTokens(
            accessToken: $access,
            expiresIn: $accessTtl,
            scope: $scope,
            refreshToken: $refresh,
            userProvider: $userProvider,
            userId: $userId,
        );
    }

    /** @param array<string, mixed> $row */
    private static function requestFrom(array $row): AuthorizationRequest
    {
        return new AuthorizationRequest(
            clientId: (string) $row['client_id'],
            redirectUri: (string) $row['redirect_uri'],
            scopes: self::scopes((string) $row['scope']),
            state: (string) $row['state'],
            codeChallenge: (string) $row['code_challenge'],
            nonce: $row['nonce'] === null ? null : (string) $row['nonce'],
            audience: (string) $row['audience'],
            sessionId: (string) $row['session_id'],
            userProvider: (string) $row['user_provider'],
            userId: (string) $row['user_id'],
        );
    }

    /**
     * A refresh may ask for less than was granted, never for more — RFC 6749 §6.
     * Asking for more is refused rather than trimmed, so a client is never left
     * believing it holds something it does not.
     *
     * @param list<string>|null $requested
     */
    private static function narrow(string $granted, ?array $requested): string
    {
        if ($requested === null || $requested === []) {
            return $granted;
        }

        $held = self::scopes($granted);

        foreach ($requested as $scope) {
            if (!in_array($scope, $held, true)) {
                throw OAuthError::refuse('invalid_scope', 'A refresh cannot widen what was granted.');
            }
        }

        return implode(' ', array_values(array_unique($requested)));
    }

    /** @return list<string> */
    private static function scopes(string $scope): array
    {
        return array_values(array_filter(explode(' ', $scope), static fn(string $s): bool => $s !== ''));
    }

    /** @param array<string, string|null> $parameters */
    private function one(string $sql, array $parameters): mixed
    {
        return $this->execute($sql, $parameters)->fetch(PDO::FETCH_ASSOC) ?: null;
    }

    /** @param array<string, string|null> $parameters */
    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->connection->prepare($sql);

        if ($statement === false || !$statement->execute($parameters)) {
            throw new RuntimeException('The token store could not be read or written.');
        }

        return $statement;
    }

    private static function token(int $bytes): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    private static function hash(#[SensitiveParameter] string $value): string
    {
        return hash('sha256', $value);
    }

    private static function challenge(#[SensitiveParameter] string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }
}
