<?php

declare(strict_types=1);

namespace Tests\Unit;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Naf\Auth\Identity\IdentityInterface;
use Naf\OAuth\Server\Core\{Claims, ClientAuthenticator, Discovery, IdTokenIssuer, ScopePolicy, TokenEndpoint, UserInfoEndpoint, Users};
use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\{AuthorizationRequest, Client, IssuedTokens};
use Naf\OAuth\Server\Store\{FileKeys, PdoTokens};
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\{Account, Schema};

/** ID tokens, UserInfo, discovery and the keys that make any of it checkable. */
final class OpenIdTest extends TestCase
{
    private const string ISSUER   = 'https://id.example.test';
    private const string VERIFIER = 'a-verifier-long-enough-to-be-one-43-chars-x';
    private const string REDIRECT = 'https://intranet.example.test/callback';

    private static ?string $pem = null;

    private PDO $connection;
    private PdoTokens $tokens;
    private FileKeys $keys;
    private Client $client;
    private string $secret;
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir() . '/naf-oidc-' . bin2hex(random_bytes(6));
        $this->keys = new FileKeys($this->path);

        // Generating RSA keys is slow; one real key is reused across the tests
        // that only need to sign with something.
        self::$pem ??= $this->keys->generate()->pem();
        $this->seed(self::$pem);

        $this->connection = Schema::migrate(Schema::connect());
        $this->tokens     = new PdoTokens($this->connection);

        [$client, $secret] = Schema::register($this->connection, grants: ['authorization_code', 'refresh_token']);
        $this->client = $client;
        $this->secret = (string) $secret;
    }

    protected function tearDown(): void
    {
        foreach (glob($this->path . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->path);
    }

    // ------------------------------------------------------- The round trip

    public function testAnIdTokenVerifiesAgainstThePublishedKeySet(): void
    {
        $issued = $this->signIn(['openid', 'email']);

        self::assertIsString($issued->idToken);

        // The whole point, done the way a relying party would: take the JWKS this
        // server publishes and check the signature with nothing else.
        $claims = (array) JWT::decode($issued->idToken, JWK::parseKeySet($this->discovery()->keys()));

        self::assertSame(self::ISSUER, $claims['iss']);
        self::assertSame($this->client->id, $claims['aud']);
        self::assertSame($this->tokens->subjectFor('database', '42'), $claims['sub']);
        self::assertGreaterThan(time(), $claims['exp']);
        self::assertLessThanOrEqual(time(), $claims['iat']);
    }

    public function testTheNonceOfThatVeryLoginIsEchoed(): void
    {
        $issued = $this->signIn(['openid'], nonce: 'n-once');

        self::assertSame('n-once', $this->decode((string) $issued->idToken)['nonce']);
    }

    public function testALoginWithoutANonceGetsNoNonceClaim(): void
    {
        self::assertArrayNotHasKey('nonce', $this->decode((string) $this->signIn(['openid'])->idToken));
    }

    public function testARefreshedIdTokenCarriesNoNonce(): void
    {
        $first = $this->signIn(['openid'], nonce: 'n-once');

        $second = $this->endpoint()->issue([
            'grant_type'    => 'refresh_token',
            'refresh_token' => (string) $first->refreshToken,
            'client_id'     => $this->client->id,
            'client_secret' => $this->secret,
        ], null);

        // OpenID Connect §12.2: the nonce belonged to the login, not to the chain.
        self::assertIsString($second->idToken);
        self::assertArrayNotHasKey('nonce', $this->decode($second->idToken));
    }

    public function testWithoutTheOpenidScopeThereIsNoIdToken(): void
    {
        self::assertNull($this->signIn(['posts.read'])->idToken);
    }

    // ------------------------------------------------------------- Claims

    public function testClaimsFollowTheScopesThatWereGranted(): void
    {
        $withEmail = $this->decode((string) $this->signIn(['openid', 'email'])->idToken);

        self::assertSame('alice@example.test', $withEmail['email']);
        self::assertTrue($withEmail['email_verified']);
        self::assertArrayNotHasKey('name', $withEmail, 'that one belongs to the profile scope');

        $without = $this->decode((string) $this->signIn(['openid'])->idToken);

        self::assertArrayNotHasKey('email', $without);
    }

    public function testTheProfileScopeReleasesTheProfile(): void
    {
        $claims = $this->decode((string) $this->signIn(['openid', 'profile'])->idToken);

        self::assertSame('Alice', $claims['name']);
        self::assertArrayNotHasKey('email', $claims);
    }

    public function testAClaimsMapperCannotChangeWhoTheTokenIsAbout(): void
    {
        $issued = $this->signIn(['openid', 'email'], mapper: static fn(): array => [
            'email' => 'alice@example.test',
            'sub'   => 'somebody-else',
            'iss'   => 'https://evil.test',
            'aud'   => 'another-client',
        ]);

        $claims = $this->decode((string) $issued->idToken);

        self::assertSame(self::ISSUER, $claims['iss']);
        self::assertSame($this->client->id, $claims['aud']);
        self::assertNotSame('somebody-else', $claims['sub']);
    }

    public function testAClaimOutsideAnyStandardScopeIsNeverReleased(): void
    {
        $issued = $this->signIn(['openid', 'profile', 'email'], mapper: static fn(): array => [
            'name'            => 'Alice',
            'internal_notes'  => 'do not ship this',
            'password_hash'   => 'certainly not this',
        ]);

        $claims = $this->decode((string) $issued->idToken);

        self::assertSame('Alice', $claims['name']);
        self::assertArrayNotHasKey('internal_notes', $claims);
        self::assertArrayNotHasKey('password_hash', $claims);
    }

    // ----------------------------------------------------------- UserInfo

    public function testUserInfoAnswersTheSameSubjectAsTheIdToken(): void
    {
        $issued = $this->signIn(['openid', 'email']);

        $answer = $this->userInfo()->forAccessToken($issued->accessToken);

        self::assertSame($this->decode((string) $issued->idToken)['sub'], $answer['sub']);
        self::assertSame('alice@example.test', $answer['email']);
    }

    public function testUserInfoNeedsTheOpenidScope(): void
    {
        $issued = $this->signIn(['posts.read']);

        $this->assertError('insufficient_scope', 403, fn() => $this->userInfo()->forAccessToken($issued->accessToken));
    }

    public function testUserInfoRefusesAnUnknownToken(): void
    {
        $this->assertError('invalid_token', 401, fn() => $this->userInfo()->forAccessToken('never-issued'));
        $this->assertError('invalid_token', 401, fn() => $this->userInfo()->forAccessToken(null));
    }

    public function testUserInfoHasNobodyToDescribeForAnApplicationToken(): void
    {
        $client = Schema::client($this->connection, grants: ['client_credentials']);
        $issued = $this->tokens->issueForClient($client, ['openid'], '', 3600);

        $this->assertError('invalid_token', 403, fn() => $this->userInfo()->forAccessToken($issued->accessToken));
    }

    // ----------------------------------------------------- Keys and rotation

    public function testRotatingSignsWithTheNewKeyAndKeepsPublishingTheOld(): void
    {
        $old    = $this->signIn(['openid']);
        $oldKid = $this->header((string) $old->idToken)['kid'];

        $this->keys->generate();

        $new    = $this->signIn(['openid']);
        $newKid = $this->header((string) $new->idToken)['kid'];

        self::assertNotSame($oldKid, $newKid, 'the new key signs from now on');

        $published = array_column($this->discovery()->keys()['keys'], 'kid');
        self::assertContains($oldKid, $published, 'tokens already out there must still verify');
        self::assertContains($newKid, $published);

        // And they do: the older token still checks out against the current set.
        JWT::decode((string) $old->idToken, JWK::parseKeySet($this->discovery()->keys()));
        $this->addToAssertionCount(1);
    }

    public function testPruningKeepsTheActiveKeyAndTheOnesStillInUse(): void
    {
        $this->keys->generate();

        self::assertCount(2, $this->keys->all());
        self::assertSame([], $this->keys->prune(86400), 'nothing is old enough yet');
        self::assertCount(2, $this->keys->all());

        // Old enough now — but the active key is never among them.
        $removed = $this->keys->prune(-1);

        self::assertCount(1, $removed);
        self::assertCount(1, $this->keys->all());
    }

    public function testAKeyIsKeptForAsLongAsWhatItSignedCanStillBeUsed(): void
    {
        // The realistic shape of the problem: a key that signed for months, a
        // token minted a moment before it was replaced, and a routine prune.
        $aged = 'oidc-' . (time() - 90 * 86400) . '-aged';
        rename($this->path . '/' . $this->keys->active()->id . '.pem', $this->path . '/' . $aged . '.pem');

        $token = (new IdTokenIssuer($this->keys, self::ISSUER, 3600))->issue('subject', 'app', null);

        $this->keys->generate();

        self::assertSame([], $this->keys->prune(7200), 'it was retired seconds ago, not 90 days ago');

        JWT::decode($token, JWK::parseKeySet($this->discovery()->keys()));
        $this->addToAssertionCount(1);
    }

    public function testAKeyIsForgottenOnceNothingItSignedCanBeUsed(): void
    {
        $first = $this->keys->active()->id;

        $this->keys->generate();

        // Long enough that everything the retired key signed has expired.
        self::assertSame([$first], $this->keys->prune(-1));
        self::assertNotContains($first, array_column($this->discovery()->keys()['keys'], 'kid'));
    }

    // ---------------------------------------------------------- Discovery

    public function testDiscoveryDescribesWhatThisServerActuallyDoes(): void
    {
        $document = $this->discovery()->document();

        self::assertSame(self::ISSUER, $document['issuer']);
        self::assertSame(self::ISSUER . '/oauth/token', $document['token_endpoint']);
        self::assertSame(['code'], $document['response_types_supported']);
        self::assertSame(['S256'], $document['code_challenge_methods_supported']);
        self::assertSame(['RS256'], $document['id_token_signing_alg_values_supported']);
        self::assertContains('openid', $document['scopes_supported']);
        self::assertContains('posts.read', $document['scopes_supported']);
        self::assertSame(self::ISSUER . '/.well-known/jwks.json', $document['jwks_uri']);
    }

    public function testWithoutAKeyItDoesNotAdvertiseWhatItCannotDo(): void
    {
        foreach (glob($this->path . '/*') ?: [] as $file) {
            unlink($file);
        }

        $document = $this->discovery()->document();

        self::assertArrayNotHasKey('jwks_uri', $document);
        self::assertArrayNotHasKey('id_token_signing_alg_values_supported', $document);
        self::assertArrayNotHasKey('userinfo_endpoint', $document);

        // Still a complete OAuth2 server, and it says so.
        self::assertSame(['code'], $document['response_types_supported']);
        self::assertSame(['keys' => []], $this->discovery()->keys());
    }

    // --------------------------------------------------------------- Machinery

    /**
     * @param list<string> $scopes
     */
    private function signIn(array $scopes, ?string $nonce = null, ?callable $mapper = null): IssuedTokens
    {
        $code = $this->tokens->issueCode(new AuthorizationRequest(
            clientId: $this->client->id,
            redirectUri: self::REDIRECT,
            scopes: $scopes,
            state: 'state-1',
            codeChallenge: rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            nonce: $nonce,
            audience: '',
            sessionId: 'session-1',
            userProvider: 'database',
            userId: '42',
        ), 60);

        return $this->endpoint($mapper)->issue([
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'code_verifier' => self::VERIFIER,
            'redirect_uri'  => self::REDIRECT,
            'client_id'     => $this->client->id,
            'client_secret' => $this->secret,
        ], null);
    }

    private function endpoint(?callable $mapper = null, bool $accountExists = true): TokenEndpoint
    {
        return new TokenEndpoint(
            authenticator: new ClientAuthenticator(Schema::clients($this->connection), Schema::hasher()),
            tokens: $this->tokens,
            idTokens: new IdTokenIssuer($this->keys, self::ISSUER),
            claims: $this->claims($mapper),
            users: $this->users($accountExists),
        );
    }

    private function userInfo(bool $accountExists = true): UserInfoEndpoint
    {
        return new UserInfoEndpoint($this->tokens, $this->claims(null), $this->users($accountExists));
    }

    private function users(bool $exists): Users
    {
        return new Users(static fn(string $provider, string $id): ?IdentityInterface
            => $exists ? new Account('42') : null);
    }

    private function claims(?callable $mapper): Claims
    {
        return new Claims(
            \Closure::fromCallable($mapper ?? static fn(): array => [
                'email'          => 'alice@example.test',
                'email_verified' => true,
                'name'           => 'Alice',
            ]),
            static fn(string $provider, string $id): ?IdentityInterface => new Account('42'),
        );
    }

    private function discovery(): Discovery
    {
        return new Discovery(self::ISSUER, new ScopePolicy(['posts.read' => 'Read posts']), $this->keys);
    }

    /** @return array<string, mixed> */
    private function decode(string $jwt): array
    {
        return (array) JWT::decode($jwt, JWK::parseKeySet($this->discovery()->keys()));
    }

    /** @return array<string, mixed> */
    private function header(string $jwt): array
    {
        $segments = explode('.', $jwt);

        return (array) json_decode((string) base64_decode(strtr($segments[0], '-_', '+/'), true), true);
    }

    private function seed(string $pem): void
    {
        @mkdir($this->path, 0700, true);
        file_put_contents($this->path . '/oidc-' . (time() - 3600) . '-' . bin2hex(random_bytes(4)) . '.pem', $pem);
    }

    private function assertError(string $error, int $status, callable $run, bool $checkStatus = true): void
    {
        try {
            $run();
        } catch (OAuthError $e) {
            self::assertSame($error, $e->error, $e->getMessage());

            if ($checkStatus) {
                self::assertSame($status, $e->status);
            }

            return;
        }

        self::fail('Expected an OAuthError "' . $error . '".');
    }

    // -------------------------------------------- Accounts that are gone

    public function testAVanishedAccountGetsNoFreshIdentityAssertion(): void
    {
        $first = $this->signIn(['openid']);

        // The account is deleted or suspended between the login and the refresh.
        try {
            $this->endpoint(accountExists: false)->issue([
                'grant_type'    => 'refresh_token',
                'refresh_token' => (string) $first->refreshToken,
                'client_id'     => $this->client->id,
                'client_secret' => $this->secret,
            ], null);
            self::fail('Expected the refresh to be refused.');
        } catch (OAuthError $e) {
            self::assertSame('invalid_grant', $e->error);
        }

        // And the chain ends here rather than waiting to be tried again.
        $this->assertError('invalid_grant', 403, fn() => $this->tokens->rotate(
            (string) $first->refreshToken, $this->client, 3600, 86400,
        ), checkStatus: false);
    }

    public function testAVanishedAccountCannotRedeemACodeEither(): void
    {
        $code = $this->tokens->issueCode(new AuthorizationRequest(
            clientId: $this->client->id,
            redirectUri: self::REDIRECT,
            scopes: ['openid'],
            state: 'state-1',
            codeChallenge: rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            nonce: null,
            audience: '',
            sessionId: 'session-1',
            userProvider: 'database',
            userId: '42',
        ), 60);

        try {
            $this->endpoint(accountExists: false)->issue([
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'code_verifier' => self::VERIFIER,
                'redirect_uri'  => self::REDIRECT,
                'client_id'     => $this->client->id,
                'client_secret' => $this->secret,
            ], null);
            self::fail('Expected the exchange to be refused.');
        } catch (OAuthError $e) {
            self::assertSame('invalid_grant', $e->error);
        }
    }

    public function testUserInfoDoesNotConfirmADeletedAccountExists(): void
    {
        $issued = $this->signIn(['openid', 'email']);

        // Answering "sub, and nothing else" would still be this server saying the
        // person is there.
        $this->assertError('invalid_token', 403, fn() => $this->userInfo(accountExists: false)
            ->forAccessToken($issued->accessToken));
    }
}
