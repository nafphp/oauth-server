<?php

declare(strict_types=1);

namespace Tests\Unit;

use NixPHP\OAuth\Server\Exception\OAuthError;
use NixPHP\OAuth\Server\Model\{AuthorizationRequest, Client};
use NixPHP\OAuth\Server\Store\PdoTokens;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/** The operations that have to be indivisible, against the real schema. */
final class PdoTokensTest extends TestCase
{
    private const string VERIFIER = 'a-verifier-long-enough-to-be-one-43-chars-x';
    private const string REDIRECT = 'https://intranet.example.test/callback';

    private PDO $connection;
    private PdoTokens $tokens;
    private Client $client;

    protected function setUp(): void
    {
        $this->connection = Schema::migrate(Schema::connect());
        $this->tokens     = new PdoTokens($this->connection);
        $this->client     = Schema::client($this->connection);
    }

    // ------------------------------------------------------------- Subjects

    public function testASubjectIsStableAndSaysNothingAboutTheAccount(): void
    {
        $subject = $this->tokens->subjectFor('database', '42');

        self::assertSame($subject, $this->tokens->subjectFor('database', '42'));
        self::assertNotSame($subject, $this->tokens->subjectFor('database', '43'));
        self::assertStringNotContainsString('database', $subject);
        self::assertStringNotContainsString('42', $subject);
    }

    public function testTheSameIdInAnotherAccountSourceIsAnotherPerson(): void
    {
        self::assertNotSame(
            $this->tokens->subjectFor('database', '42'),
            $this->tokens->subjectFor('ldap', '42'),
        );
    }

    // --------------------------------------------------- Consent, and its binding

    public function testConsentIsBoundToTheRequestTheBrowserAndThePerson(): void
    {
        $id = $this->tokens->storeRequest($this->request(), 600);

        $taken = $this->tokens->consumeRequest($id, 'session-1', 'database', '42');

        self::assertSame($this->client->id, $taken->clientId);
        self::assertSame(['posts.read'], $taken->scopes);
    }

    public function testConsentCannotBeGivenTwice(): void
    {
        $id = $this->tokens->storeRequest($this->request(), 600);
        $this->tokens->consumeRequest($id, 'session-1', 'database', '42');

        $this->assertError('invalid_request', fn() => $this->tokens->consumeRequest($id, 'session-1', 'database', '42'));
    }

    public function testConsentCannotBeGivenFromAnotherBrowser(): void
    {
        $id = $this->tokens->storeRequest($this->request(), 600);

        $this->assertError('invalid_request', fn() => $this->tokens->consumeRequest($id, 'session-2', 'database', '42'));
    }

    public function testConsentCannotBeGivenByAnotherPerson(): void
    {
        $id = $this->tokens->storeRequest($this->request(), 600);

        $this->assertError('invalid_request', fn() => $this->tokens->consumeRequest($id, 'session-1', 'database', '99'));
    }

    public function testAnExpiredRequestIsGone(): void
    {
        $id = $this->tokens->storeRequest($this->request(), -1);

        $this->assertError('invalid_request', fn() => $this->tokens->consumeRequest($id, 'session-1', 'database', '42'));
    }

    // ------------------------------------------------------ Redeeming a code

    public function testACodeBecomesAnAccessAndARefreshToken(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        self::assertSame('posts.read', $issued->scope);
        self::assertNotNull($issued->refreshToken);
        self::assertSame('Bearer', $issued->body()['token_type']);

        $record = $this->tokens->inspect($issued->accessToken);

        self::assertSame('database', $record?->userProvider);
        self::assertSame('42', $record?->userId);
        self::assertTrue($record?->hasScope('posts.read'));
        self::assertFalse($record?->isApplication());
    }

    public function testACodeUsedTwiceTakesEverythingItProducedWithIt(): void
    {
        $code   = $this->code();
        $issued = $this->tokens->redeem($code, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        self::assertNotNull($this->tokens->inspect($issued->accessToken), 'precondition');

        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));

        // A replayed code means the first exchange cannot be trusted either.
        self::assertNull($this->tokens->inspect($issued->accessToken));
        $this->assertError('invalid_grant', fn() => $this->tokens->rotate((string) $issued->refreshToken, $this->client, 3600, 86400));
    }

    public function testAWrongVerifierBurnsTheCode(): void
    {
        $code = $this->code();

        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $this->client, self::REDIRECT, 'not-the-verifier', 3600, 86400));

        // The code has been somewhere it should not have been, so the real client
        // does not get to use it either.
        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));
    }

    public function testAWrongRedirectUriBurnsTheCode(): void
    {
        $code = $this->code();

        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $this->client, 'https://evil.test/cb', self::VERIFIER, 3600, 86400));
        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));
    }

    public function testAnotherClientCannotUseTheCode(): void
    {
        $other = Schema::client($this->connection);
        $code  = $this->code();

        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $other, self::REDIRECT, self::VERIFIER, 3600, 86400));
    }

    public function testAnExpiredOrUnknownCodeIsRefused(): void
    {
        $this->assertError('invalid_grant', fn() => $this->tokens->redeem('never-issued', $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));
        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($this->code(ttl: -1), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));
    }

    public function testAClientWithoutTheRefreshGrantGetsNoRefreshToken(): void
    {
        $client = Schema::client($this->connection, grants: ['authorization_code']);
        $issued = $this->tokens->redeem($this->code($client), $client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        self::assertNull($issued->refreshToken);
        self::assertArrayNotHasKey('refresh_token', $issued->body());
    }

    // ---------------------------------------------------------- Rotation

    public function testRotatingReplacesBothTokens(): void
    {
        $first = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $second = $this->tokens->rotate((string) $first->refreshToken, $this->client, 3600, 86400);

        self::assertNotSame($first->accessToken, $second->accessToken);
        self::assertNotSame($first->refreshToken, $second->refreshToken);
        self::assertNotNull($this->tokens->inspect($second->accessToken));
        self::assertNull($this->tokens->inspect($first->accessToken), 'a rotation leaves no second live token');
    }

    public function testASpentRefreshTokenComingBackEndsTheWholeChain(): void
    {
        $first  = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);
        $second = $this->tokens->rotate((string) $first->refreshToken, $this->client, 3600, 86400);

        $this->assertError('invalid_grant', fn() => $this->tokens->rotate((string) $first->refreshToken, $this->client, 3600, 86400));

        // Somebody has a copy, so nothing from that authorization survives.
        self::assertNull($this->tokens->inspect($second->accessToken));
        $this->assertError('invalid_grant', fn() => $this->tokens->rotate((string) $second->refreshToken, $this->client, 3600, 86400));
    }

    public function testAnotherClientCannotRotateIt(): void
    {
        $other  = Schema::client($this->connection);
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $this->assertError('invalid_grant', fn() => $this->tokens->rotate((string) $issued->refreshToken, $other, 3600, 86400));
    }

    // ------------------------------------------------------ Client credentials

    public function testAnApplicationTokenHasNobodyBehindIt(): void
    {
        $client = Schema::client($this->connection, grants: ['client_credentials']);
        $issued = $this->tokens->issueForClient($client, ['posts.read'], '', 3600);

        self::assertNull($issued->refreshToken, 'it can always ask again with its own credentials');

        $record = $this->tokens->inspect($issued->accessToken);

        self::assertTrue($record?->isApplication());
        self::assertNull($record?->userId);
    }

    // ----------------------------------------------------------- Inspecting

    public function testAnExpiredTokenIsNotALiveToken(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, -1, 86400);

        self::assertNull($this->tokens->inspect($issued->accessToken));
    }

    public function testAnUnknownTokenIsNotALiveToken(): void
    {
        self::assertNull($this->tokens->inspect('never-issued'));
    }

    // ------------------------------------------------------------- Revoking

    public function testRevokingAnAccessTokenLeavesTheRefreshTokenAlone(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $this->tokens->revoke($issued->accessToken, $this->client);

        self::assertNull($this->tokens->inspect($issued->accessToken));
        self::assertNotNull($this->tokens->rotate((string) $issued->refreshToken, $this->client, 3600, 86400));
    }

    public function testRevokingARefreshTokenEndsTheAuthorization(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $this->tokens->revoke((string) $issued->refreshToken, $this->client);

        self::assertNull($this->tokens->inspect($issued->accessToken));
        $this->assertError('invalid_grant', fn() => $this->tokens->rotate((string) $issued->refreshToken, $this->client, 3600, 86400));
    }

    public function testAClientCannotRevokeSomebodyElsesToken(): void
    {
        $other  = Schema::client($this->connection);
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $this->tokens->revoke($issued->accessToken, $other);

        self::assertNotNull($this->tokens->inspect($issued->accessToken));
    }

    // -------------------------------------- Two connections, one authorization

    public function testASecondConnectionSeesTheCodeIsSpent(): void
    {
        $file = sys_get_temp_dir() . '/nixphp-oauth-server-' . bin2hex(random_bytes(6)) . '.sqlite';

        try {
            $a      = Schema::migrate(Schema::connect($file));
            $client = Schema::client($a);
            $first  = new PdoTokens($a);
            $code   = $this->codeOn($first, $client);

            $issued = $first->redeem($code, $client, self::REDIRECT, self::VERIFIER, 3600, 86400);

            // A different connection entirely: the claim lives in the database, not
            // in this process.
            $second = new PdoTokens(Schema::connect($file));

            $this->assertError('invalid_grant', fn() => $second->redeem($code, $client, self::REDIRECT, self::VERIFIER, 3600, 86400));
            self::assertNull($second->inspect($issued->accessToken), 'the replay revoked it across connections');
        } finally {
            @unlink($file);
        }
    }

    // --------------------------------------------------------------- Machinery

    private function request(?Client $client = null): AuthorizationRequest
    {
        return new AuthorizationRequest(
            clientId: ($client ?? $this->client)->id,
            redirectUri: self::REDIRECT,
            scopes: ['posts.read'],
            state: 'state-1',
            codeChallenge: rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            nonce: null,
            audience: '',
            sessionId: 'session-1',
            userProvider: 'database',
            userId: '42',
        );
    }

    private function code(?Client $client = null, int $ttl = 60): string
    {
        return $this->tokens->issueCode($this->request($client), $ttl);
    }

    private function codeOn(PdoTokens $tokens, Client $client): string
    {
        return $tokens->issueCode($this->request($client), 60);
    }

    private function assertError(string $error, callable $run): void
    {
        try {
            $run();
        } catch (OAuthError $e) {
            self::assertSame($error, $e->error, $e->getMessage());
            return;
        }

        self::fail('Expected an OAuthError "' . $error . '".');
    }

    // --------------------------------------------------- Transactions

    public function testARefusedScopeLeavesNothingHalfOpen(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $this->assertError('invalid_scope', fn() => $this->tokens->rotate(
            (string) $issued->refreshToken, $this->client, 3600, 86400, ['posts.write'],
        ));

        // An open transaction survives the request and takes its locks with it.
        self::assertFalse($this->connection->inTransaction());
    }

    public function testAWithdrawnFamilyLeavesNothingHalfOpen(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);
        $family = (string) $this->connection->query('SELECT family_id FROM oauth_families')?->fetchColumn();

        $this->tokens->revokeFamily($family);

        $this->assertError('invalid_grant', fn() => $this->tokens->rotate(
            (string) $issued->refreshToken, $this->client, 3600, 86400,
        ));

        self::assertFalse($this->connection->inTransaction());
    }

    public function testARefusedScopeDoesNotSpendTheRefreshToken(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        $this->assertError('invalid_scope', fn() => $this->tokens->rotate(
            (string) $issued->refreshToken, $this->client, 3600, 86400, ['posts.write'],
        ));

        // Asking for the wrong thing is the client's mistake, not a reason to end
        // the authorization: the same token still works when it asks properly.
        self::assertNotNull($this->tokens->rotate((string) $issued->refreshToken, $this->client, 3600, 86400));
    }

    // ------------------------------------------------------- Families

    public function testACodeBelongsToAFamilyFromTheMomentItIsIssued(): void
    {
        $this->tokens->issueCode($this->request(), 60);

        $family = $this->connection->query('SELECT family_id FROM oauth_families')?->fetchColumn();

        self::assertIsString($family);
        self::assertSame($family, $this->connection->query('SELECT family_id FROM oauth_codes')?->fetchColumn());
    }

    public function testAWithdrawnAuthorizationCannotBeRedeemedEvenWithAFreshCode(): void
    {
        $code   = $this->code();
        $family = (string) $this->connection->query('SELECT family_id FROM oauth_codes')?->fetchColumn();

        $this->tokens->revokeFamily($family);

        // The code itself has never been used. The authorization behind it is gone,
        // and that is what decides.
        $this->assertError('invalid_grant', fn() => $this->tokens->redeem($code, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));
    }

    public function testAWithdrawnAuthorizationStopsFurtherRotation(): void
    {
        $issued = $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);
        $family = (string) $this->connection->query('SELECT family_id FROM oauth_families')?->fetchColumn();

        $this->tokens->revokeFamily($family);

        $this->assertError('invalid_grant', fn() => $this->tokens->rotate((string) $issued->refreshToken, $this->client, 3600, 86400));
        self::assertNull($this->tokens->inspect($issued->accessToken));
    }

    public function testWithdrawingTwiceChangesNothing(): void
    {
        $this->tokens->redeem($this->code(), $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);
        $family = (string) $this->connection->query('SELECT family_id FROM oauth_families')?->fetchColumn();

        $this->tokens->revokeFamily($family);
        $first = $this->connection->query('SELECT revoked_at FROM oauth_families')?->fetchColumn();

        $this->tokens->revokeFamily($family);

        self::assertSame($first, $this->connection->query('SELECT revoked_at FROM oauth_families')?->fetchColumn());
    }

    public function testEachAuthorizationGetsItsOwnFamily(): void
    {
        $first  = $this->code();
        $second = $this->code();

        $families = $this->connection->query('SELECT DISTINCT family_id FROM oauth_codes')?->fetchAll(PDO::FETCH_COLUMN);

        self::assertCount(2, (array) $families, 'one compromised authorization must not end another');

        // Withdrawing one leaves the other alone.
        $this->tokens->revokeFamily((string) $this->connection
            ->query("SELECT family_id FROM oauth_codes WHERE code_hash = '" . hash('sha256', $first) . "'")?->fetchColumn());

        self::assertNotNull($this->tokens->redeem($second, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400));
    }
}
