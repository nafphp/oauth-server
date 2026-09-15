<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Core\Authorization;
use Naf\OAuth\Server\Core\Consent;
use Naf\OAuth\Server\Core\ScopePolicy;
use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Store\PdoTokens;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/** Checking the request, asking the person, issuing the code — and in that order. */
final class AuthorizationTest extends TestCase
{
    private const string VERIFIER = 'a-verifier-long-enough-to-be-one-43-chars-x';
    private const string REDIRECT = 'https://intranet.example.test/callback';

    private PDO $connection;
    private PdoTokens $tokens;
    private Client $client;

    /** @var list<string> */
    private array $held = ['posts.view', 'posts.edit'];

    protected function setUp(): void
    {
        $this->connection = Schema::migrate(Schema::connect());
        $this->tokens     = new PdoTokens($this->connection);
        $this->client     = Schema::client($this->connection);
    }

    // ------------------------------------ Before a redirect URI is established

    public function testAnUnknownClientIsNeverRedirectedAnywhere(): void
    {
        $this->assertNotRedirectable('invalid_client', fn() => $this->begin(['client_id' => 'nope']));
    }

    public function testARequestWithoutAClientIsRefused(): void
    {
        $this->assertNotRedirectable('invalid_request', fn() => $this->begin(['client_id' => null]));
    }

    public function testTheRequestHasToNameWhereItWantsToGoBack(): void
    {
        // Even with one registered URI. The same value has to come back at the
        // token endpoint, and a request that never named one cannot be held to it.
        $this->assertNotRedirectable('invalid_request', fn() => $this->begin(['redirect_uri' => null]));
    }

    public function testAnUnregisteredRedirectUriIsNeverRedirectedTo(): void
    {
        // The whole point: an error sent to an address nobody vouched for is an
        // open redirect wearing an official-looking error message.
        $error = $this->assertNotRedirectable('invalid_request', fn() => $this->begin(['redirect_uri' => 'https://evil.test/cb']));

        self::assertNull($error->redirectTarget());
    }

    // ------------------------------------- Once it is, the client can be told

    public function testTheWrongResponseTypeGoesBackToTheClient(): void
    {
        $target = $this->assertRedirectable('unsupported_response_type', fn() => $this->begin(['response_type' => 'token']));

        self::assertStringStartsWith(self::REDIRECT . '?', $target);
        self::assertStringContainsString('error=unsupported_response_type', $target);
        self::assertStringContainsString('state=state-1', $target);
    }

    public function testPkceIsNotOptional(): void
    {
        $this->assertRedirectable('invalid_request', fn() => $this->begin(['code_challenge' => null]));
        $this->assertRedirectable('invalid_request', fn() => $this->begin(['code_challenge_method' => 'plain']));
    }

    public function testAClientWithoutTheGrantIsRefused(): void
    {
        $client = Schema::client($this->connection, grants: ['client_credentials']);

        $this->assertRedirectable('unauthorized_client', fn() => $this->begin([], $client));
    }

    public function testAScopeBeyondTheRegistrationIsRefused(): void
    {
        $this->assertRedirectable('invalid_scope', fn() => $this->begin(['scope' => 'posts.read users.delete']));
    }

    public function testAScopeThisServerDoesNotOfferIsRefused(): void
    {
        // Registered for a scope this server does not offer at all.
        [$registered] = Schema::clients($this->connection)
            ->register('Acme', [self::REDIRECT], ['authorization_code'], ['unknown.scope'], confidential: false);

        $this->assertRedirectable('invalid_scope', fn() => $this->begin(['scope' => 'unknown.scope'], $registered));
    }

    public function testWhatThisServerDoesNotDoIsSaidOutLoud(): void
    {
        // Ignoring these is the worst available answer: a relying party that asked
        // for re-authentication and got an ordinary session back has been told
        // something untrue about the person in front of it.
        $this->assertRedirectable('interaction_required', fn() => $this->begin(['prompt' => 'none']));
        $this->assertRedirectable('invalid_request', fn() => $this->begin(['prompt' => 'login']));
        $this->assertRedirectable('invalid_request', fn() => $this->begin(['max_age' => '0']));
    }

    public function testConsentIsStillOfferedForPromptsWeCanSatisfy(): void
    {
        self::assertNotNull($this->begin(['prompt' => 'consent'])->requestId);
    }

    public function testOpenidIsNotOfferedWithoutTheMeansToAnswerIt(): void
    {
        [$client] = Schema::clients($this->connection)
            ->register('Acme', [self::REDIRECT], ['authorization_code'], ['openid'], confidential: false);

        // Otherwise a client asks for OpenID Connect, a person agrees to it, and
        // the token response quietly contains no ID token.
        $target = $this->assertRedirectable('invalid_scope', fn() => $this->begin(['scope' => 'openid'], $client));

        self::assertStringContainsString('oauth%3Akeys%3Agenerate', $target);
    }

    // ------------------------------------------- Scopes and what a person holds

    public function testAScopeIsOnlyOfferedWhenThePersonHoldsItsPermission(): void
    {
        $this->held = ['posts.view'];

        $consent = $this->begin(['scope' => 'posts.read posts.write']);

        self::assertSame([['scope' => 'posts.read', 'label' => 'Read posts']], $consent->scopes);
    }

    public function testHoldingNoneOfThemIsARefusal(): void
    {
        $this->held = [];

        $this->assertRedirectable('access_denied', fn() => $this->begin(['scope' => 'posts.read']));
    }

    public function testAskingForNothingOffersWhatTheClientMayHave(): void
    {
        $consent = $this->begin(['scope' => null]);

        self::assertSame(['posts.read', 'posts.write'], array_column($consent->scopes, 'scope'));
        self::assertSame('Acme Intranet', $consent->clientName);
    }

    // --------------------------------------------------------- Deciding

    public function testApprovingIssuesACodeThatRedeems(): void
    {
        $consent = $this->begin();

        $target = $this->authorization()->approve($consent->requestId, 'session-1', 'database', '42');

        self::assertStringStartsWith(self::REDIRECT . '?', $target);
        parse_str((string) parse_url($target, PHP_URL_QUERY), $parameters);
        self::assertSame('state-1', $parameters['state']);

        $issued = $this->tokens->redeem($parameters['code'], $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        self::assertSame('posts.read posts.write', $issued->scope);
    }

    public function testDenyingTellsTheClientSo(): void
    {
        $consent = $this->begin();

        $target = $this->authorization()->deny($consent->requestId, 'session-1', 'database', '42');

        self::assertStringContainsString('error=access_denied', $target);
        self::assertStringContainsString('state=state-1', $target);
    }

    public function testConsentCannotBeGivenTwice(): void
    {
        $consent = $this->begin();
        $this->authorization()->approve($consent->requestId, 'session-1', 'database', '42');

        $this->assertNotRedirectable('invalid_request', fn() => $this->authorization()
            ->approve($consent->requestId, 'session-1', 'database', '42'));
    }

    public function testConsentCannotBeGivenByAnybodyElse(): void
    {
        $consent = $this->begin();

        $this->assertNotRedirectable('invalid_request', fn() => $this->authorization()
            ->approve($consent->requestId, 'session-1', 'database', '99'));
    }

    public function testNothingAboutTheRequestTravelsThroughTheBrowser(): void
    {
        $consent = $this->begin();

        // The browser is handed an opaque id and nothing else — no client, no
        // scope, no redirect URI to post back a different version of.
        self::assertStringNotContainsString($this->client->id, $consent->requestId);
        self::assertStringNotContainsString('posts', $consent->requestId);
        self::assertStringNotContainsString('example.test', $consent->requestId);
    }

    // --------------------------------------------------------------- Machinery

    private function authorization(): Authorization
    {
        return new Authorization(
            clients: Schema::clients($this->connection),
            tokens: $this->tokens,
            policy: new ScopePolicy([
                'posts.read'  => ['label' => 'Read posts', 'permission' => 'posts.view'],
                'posts.write' => ['label' => 'Write posts', 'permission' => 'posts.edit'],
            ]),
            holdsPermission: fn(string $permission): bool => in_array($permission, $this->held, true),
        );
    }

    /** @param array<string, string|null> $overrides */
    private function begin(array $overrides = [], ?Client $client = null): Consent
    {
        $query = $overrides + [
            'client_id'             => ($client ?? $this->client)->id,
            'redirect_uri'          => self::REDIRECT,
            'response_type'         => 'code',
            'scope'                 => 'posts.read posts.write',
            'state'                 => 'state-1',
            'code_challenge'        => rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ];

        return $this->authorization()->begin(
            array_filter($query, static fn(mixed $value): bool => $value !== null),
            'session-1',
            'database',
            '42',
        );
    }

    private function assertNotRedirectable(string $error, callable $run): OAuthError
    {
        try {
            $run();
        } catch (OAuthError $e) {
            self::assertSame($error, $e->error, $e->getMessage());
            self::assertFalse($e->redirectable, 'this error must not leave our own page');

            return $e;
        }

        self::fail('Expected an OAuthError "' . $error . '".');
    }

    private function assertRedirectable(string $error, callable $run): string
    {
        try {
            $run();
        } catch (OAuthError $e) {
            self::assertSame($error, $e->error, $e->getMessage());

            $target = $e->redirectTarget();

            self::assertIsString($target, 'a redirectable error needs somewhere to go');

            return $target;
        }

        self::fail('Expected an OAuthError "' . $error . '".');
    }
}
