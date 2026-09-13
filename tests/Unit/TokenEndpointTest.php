<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Core\{ClientAuthenticator, TokenEndpoint};
use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\{AuthorizationRequest, Client};
use Naf\OAuth\Server\Store\PdoTokens;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/** The grants, and who may ask for them. */
final class TokenEndpointTest extends TestCase
{
    private const string VERIFIER = 'a-verifier-long-enough-to-be-one-43-chars-x';
    private const string REDIRECT = 'https://intranet.example.test/callback';

    private PDO $connection;
    private PdoTokens $tokens;
    private TokenEndpoint $endpoint;
    private Client $client;
    private string $secret;

    protected function setUp(): void
    {
        $this->connection = Schema::migrate(Schema::connect());
        $this->tokens     = new PdoTokens($this->connection);

        [$client, $secret] = Schema::register($this->connection, grants: [
            'authorization_code', 'refresh_token', 'client_credentials', 'introspection',
        ]);

        $this->client = $client;
        $this->secret = (string) $secret;

        $this->endpoint = new TokenEndpoint(
            new ClientAuthenticator(Schema::clients($this->connection), Schema::hasher()),
            $this->tokens,
        );
    }

    // ------------------------------------------------------ Authorization code

    public function testACodeBecomesTokens(): void
    {
        $issued = $this->endpoint->issue($this->credentials([
            'grant_type'    => 'authorization_code',
            'code'          => $this->code(),
            'code_verifier' => self::VERIFIER,
            'redirect_uri'  => self::REDIRECT,
        ]), null);

        self::assertSame('Bearer', $issued->body()['token_type']);
        self::assertNotNull($issued->refreshToken);
    }

    public function testTheVerifierIsNotOptional(): void
    {
        $this->assertError('invalid_request', fn() => $this->endpoint->issue($this->credentials([
            'grant_type' => 'authorization_code',
            'code'       => $this->code(),
        ]), null));
    }

    public function testTheRedirectUriIsNotOptional(): void
    {
        // PKCE binds the exchange to the browser that started it; this binds it to
        // where the code was sent. Different questions, RFC 6749 §4.1.3 asks both.
        $this->assertError('invalid_request', fn() => $this->endpoint->issue($this->credentials([
            'grant_type'    => 'authorization_code',
            'code'          => $this->code(),
            'code_verifier' => self::VERIFIER,
        ]), null));
    }

    public function testACodeIsRequired(): void
    {
        $this->assertError('invalid_request', fn() => $this->endpoint->issue($this->credentials([
            'grant_type'    => 'authorization_code',
            'code_verifier' => self::VERIFIER,
        ]), null));
    }

    // --------------------------------------------------------------- Refresh

    public function testARefreshTokenBecomesANewPair(): void
    {
        $first = $this->issueFromCode();

        $second = $this->endpoint->issue($this->credentials([
            'grant_type'    => 'refresh_token',
            'refresh_token' => (string) $first->refreshToken,
        ]), null);

        self::assertNotSame($first->accessToken, $second->accessToken);
    }

    public function testARefreshMayAskForLess(): void
    {
        $first = $this->issueFromCode();

        $second = $this->endpoint->issue($this->credentials([
            'grant_type'    => 'refresh_token',
            'refresh_token' => (string) $first->refreshToken,
            'scope'         => 'posts.read',
        ]), null);

        self::assertSame('posts.read', $second->scope);
    }

    public function testARefreshCannotAskForMore(): void
    {
        $first = $this->issueFromCode(scopes: ['posts.read']);

        $this->assertError('invalid_scope', fn() => $this->endpoint->issue($this->credentials([
            'grant_type'    => 'refresh_token',
            'refresh_token' => (string) $first->refreshToken,
            'scope'         => 'posts.read posts.write',
        ]), null));
    }

    // ----------------------------------------------------- Client credentials

    public function testAnApplicationCanActForItself(): void
    {
        $issued = $this->endpoint->issue($this->credentials([
            'grant_type' => 'client_credentials',
            'scope'      => 'posts.read',
        ]), null);

        self::assertNull($issued->refreshToken);
        self::assertTrue($this->tokens->inspect($issued->accessToken)?->isApplication());
    }

    public function testAPublicClientCannotActForItself(): void
    {
        [$public] = Schema::register($this->connection, grants: ['client_credentials'], confidential: false);

        $this->assertError('invalid_client', fn() => $this->endpoint->issue([
            'grant_type' => 'client_credentials',
            'client_id'  => $public->id,
        ], null));
    }

    // ---------------------------------------------------------------- Grants

    public function testAnUnknownGrantIsNamedAsSuch(): void
    {
        $this->assertError('unsupported_grant_type', fn() => $this->endpoint->issue($this->credentials([
            'grant_type' => 'password',
        ]), null));

        $this->assertError('unsupported_grant_type', fn() => $this->endpoint->issue($this->credentials([]), null));
    }

    public function testAGrantTheClientIsNotRegisteredForIsRefused(): void
    {
        [$limited, $secret] = Schema::register($this->connection, grants: ['authorization_code']);

        $this->assertError('unauthorized_client', fn() => $this->endpoint->issue([
            'grant_type'    => 'client_credentials',
            'client_id'     => $limited->id,
            'client_secret' => (string) $secret,
        ], null));
    }

    // -------------------------------------------------------------- Revoking

    public function testRevokingAnUnknownTokenIsStillSuccess(): void
    {
        // RFC 7009 §2.2. Anything else would make this a way of asking which
        // tokens exist.
        $this->endpoint->revoke($this->credentials(['token' => 'never-issued']), null);

        $this->addToAssertionCount(1);
    }

    public function testRevokingWorks(): void
    {
        $issued = $this->issueFromCode();

        $this->endpoint->revoke($this->credentials(['token' => $issued->accessToken]), null);

        self::assertNull($this->tokens->inspect($issued->accessToken));
    }

    // ----------------------------------------------------------- Introspection

    public function testIntrospectionNeedsToBeGranted(): void
    {
        [$other, $secret] = Schema::register($this->connection, grants: ['authorization_code']);

        $this->assertError('unauthorized_client', fn() => $this->endpoint->introspect([
            'client_id'     => $other->id,
            'client_secret' => (string) $secret,
            'token'         => 'anything',
        ], null));
    }

    public function testAPublicClientCannotIntrospectEvenIfTheRowSaysItMay(): void
    {
        // The registry refuses this combination outright. Put the database into it
        // anyway — an older row, a hand-edited one — because the endpoint must not
        // rely on nothing upstream ever having slipped.
        $this->connection->exec(
            "UPDATE oauth_clients SET secret_hash = NULL WHERE client_id = '" . $this->client->id . "'"
        );

        // Identified by a client id anybody can read out of an authorize URL, and
        // authenticated by nothing at all.
        $this->assertError('unauthorized_client', fn() => $this->endpoint->introspect(
            ['client_id' => $this->client->id, 'token' => 'anything'],
            null,
        ));
    }

    public function testAnUnknownTokenIsSimplyInactive(): void
    {
        $answer = $this->endpoint->introspect($this->credentials(['token' => 'never-issued']), null);

        self::assertSame(['active' => false], $answer);
    }

    public function testIntrospectionShowsTheSubjectAndNotTheAccount(): void
    {
        $issued = $this->issueFromCode();

        $answer = $this->endpoint->introspect($this->credentials(['token' => $issued->accessToken]), null);

        self::assertTrue($answer['active']);
        self::assertSame($this->client->id, $answer['client_id']);
        self::assertSame('posts.read posts.write', $answer['scope']);
        self::assertSame($this->tokens->subjectFor('database', '42'), $answer['sub']);
        self::assertStringNotContainsString('database', (string) $answer['sub']);
        self::assertNotSame('42', $answer['sub']);
    }

    // --------------------------------------------------------------- Machinery

    /** @param array<string, mixed> $body @return array<string, mixed> */
    private function credentials(array $body): array
    {
        return $body + ['client_id' => $this->client->id, 'client_secret' => $this->secret];
    }

    /** @param list<string> $scopes */
    private function code(array $scopes = ['posts.read', 'posts.write']): string
    {
        return $this->tokens->issueCode(new AuthorizationRequest(
            clientId: $this->client->id,
            redirectUri: self::REDIRECT,
            scopes: $scopes,
            state: 'state-1',
            codeChallenge: rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            nonce: null,
            audience: '',
            sessionId: 'session-1',
            userProvider: 'database',
            userId: '42',
        ), 60);
    }

    /** @param list<string> $scopes */
    private function issueFromCode(array $scopes = ['posts.read', 'posts.write']): \Naf\OAuth\Server\Model\IssuedTokens
    {
        return $this->endpoint->issue($this->credentials([
            'grant_type'    => 'authorization_code',
            'code'          => $this->code($scopes),
            'code_verifier' => self::VERIFIER,
            'redirect_uri'  => self::REDIRECT,
        ]), null);
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
}
