<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Core\ResourceServer;
use Naf\OAuth\Server\Core\ScopePolicy;
use Naf\OAuth\Server\Core\TokenContext;
use Naf\OAuth\Server\Model\AuthorizationRequest;
use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Store\PdoTokens;
use Nyholm\Psr7\ServerRequest;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/** Which tokens this API accepts — and which perfectly valid ones it does not. */
final class ResourceServerTest extends TestCase
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
        $this->client     = Schema::client($this->connection, grants: ['authorization_code', 'refresh_token', 'client_credentials']);
    }

    public function testATokenForThisApiIsAccepted(): void
    {
        $issued = $this->tokens->issueForClient($this->client, ['posts.read'], '', 3600);

        self::assertTrue($this->context($issued->accessToken)->can('posts.read'));
    }

    public function testATokenGrantedForAnotherApiIsNotAWeakerTokenHereButNoTokenAtAll(): void
    {
        $issued = $this->tokens->issueForClient($this->client, ['posts.read'], 'https://other-api.test', 3600);

        $context = $this->context($issued->accessToken);

        self::assertFalse($context->active());
        self::assertFalse($context->can('posts.read'));
        self::assertNull($context->clientId());
    }

    public function testAnApiThatNamesItselfRefusesTokensWithoutThatName(): void
    {
        $issued = $this->tokens->issueForClient($this->client, ['posts.read'], '', 3600);

        self::assertFalse($this->context($issued->accessToken, 'https://reports.example.test')->active());
    }

    public function testWithdrawingAClientTakesItsTokensWithIt(): void
    {
        $issued = $this->tokens->issueForClient($this->client, ['posts.read'], '', 3600);

        self::assertTrue($this->context($issued->accessToken)->active(), 'precondition');

        Schema::clients($this->connection)->revoke($this->client->id);

        // Otherwise revoking a client means nothing until its tokens expire.
        self::assertFalse($this->context($issued->accessToken)->active());
        self::assertNull($this->tokens->inspect($issued->accessToken));
    }

    public function testTheTargetSurvivesEveryRefresh(): void
    {
        $code = $this->tokens->issueCode(new AuthorizationRequest(
            clientId: $this->client->id,
            redirectUri: self::REDIRECT,
            scopes: ['posts.read'],
            state: 'state-1',
            codeChallenge: rtrim(strtr(base64_encode(hash('sha256', self::VERIFIER, true)), '+/', '-_'), '='),
            nonce: null,
            audience: 'https://reports.example.test',
            sessionId: 'session-1',
            userProvider: 'database',
            userId: '42',
        ), 60);

        $first = $this->tokens->redeem($code, $this->client, self::REDIRECT, self::VERIFIER, 3600, 86400);

        // What the person authorized, not what the registration happens to say now.
        self::assertSame('https://reports.example.test', $this->tokens->inspect($first->accessToken)?->audience);

        // A rotation retires the token it replaces, so ask about the new one.
        $second = $this->tokens->rotate((string) $first->refreshToken, $this->client, 3600, 86400);

        self::assertSame('https://reports.example.test', $this->tokens->inspect($second->accessToken)?->audience);
        self::assertNull($this->tokens->inspect($first->accessToken), 'the replaced token is gone');
    }

    private function context(string $token, string $audience = ''): TokenContext
    {
        return (new ResourceServer(
            $this->tokens,
            new ScopePolicy(['posts.read' => ['label' => 'Read', 'permission' => null]]),
            static fn(): null => null,
            new ServerRequest('GET', 'https://api.example.test/x', ['Authorization' => 'Bearer ' . $token]),
            $audience,
        ))->context();
    }
}
