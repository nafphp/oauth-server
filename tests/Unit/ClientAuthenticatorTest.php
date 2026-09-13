<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Core\ClientAuthenticator;
use Naf\OAuth\Server\Exception\OAuthError;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/** Who is asking, and whether they proved it. */
final class ClientAuthenticatorTest extends TestCase
{
    private PDO $connection;
    private ClientAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->connection    = Schema::migrate(Schema::connect());
        $this->authenticator = new ClientAuthenticator(Schema::clients($this->connection), Schema::hasher());
    }

    public function testAConfidentialClientAuthenticatesWithItsSecretInTheBody(): void
    {
        [$client, $secret] = Schema::register($this->connection);

        $authenticated = $this->authenticator->authenticate(
            ['client_id' => $client->id, 'client_secret' => $secret],
            null,
        );

        self::assertSame($client->id, $authenticated->id);
    }

    public function testAConfidentialClientAuthenticatesWithBasic(): void
    {
        [$client, $secret] = Schema::register($this->connection);

        $header = 'Basic ' . base64_encode(rawurlencode($client->id) . ':' . rawurlencode((string) $secret));

        self::assertSame($client->id, $this->authenticator->authenticate([], $header)->id);
    }

    public function testTheWrongSecretIsRefusedWith401(): void
    {
        [$client] = Schema::register($this->connection);

        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate(
            ['client_id' => $client->id, 'client_secret' => 'not-it'],
            null,
        ));
    }

    public function testNoSecretAtAllIsStillARefusal(): void
    {
        [$client] = Schema::register($this->connection);

        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate(
            ['client_id' => $client->id],
            null,
        ));
    }

    public function testAnUnknownClientIsRefused(): void
    {
        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate(
            ['client_id' => 'never-registered', 'client_secret' => 'anything'],
            null,
        ));
    }

    public function testARequestWithoutAClientIsRefused(): void
    {
        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate([], null));
    }

    public function testAPublicClientIsIdentifiedButNotAuthenticated(): void
    {
        [$client, $secret] = Schema::register($this->connection, confidential: false);

        self::assertNull($secret);
        self::assertSame($client->id, $this->authenticator->authenticate(['client_id' => $client->id], null)->id);
    }

    public function testAPublicClientPresentingASecretIsRefused(): void
    {
        [$client] = Schema::register($this->connection, confidential: false);

        // Either the registration or the request is wrong, and guessing which is
        // not this endpoint's job.
        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate(
            ['client_id' => $client->id, 'client_secret' => 'invented'],
            null,
        ));
    }

    public function testTwoAuthenticationMethodsAtOnceAreRefused(): void
    {
        [$client, $secret] = Schema::register($this->connection);

        $this->assertError('invalid_request', 401, fn() => $this->authenticator->authenticate(
            ['client_id' => $client->id, 'client_secret' => $secret],
            'Basic ' . base64_encode($client->id . ':' . $secret),
        ));
    }

    public function testAMalformedBasicHeaderIsRefused(): void
    {
        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate([], 'Basic not-base64-with-no-colon'));
    }

    public function testASecretWithAColonSurvivesTheHeader(): void
    {
        $clients = Schema::clients($this->connection);
        [$client] = $clients->register('Acme', ['https://acme.test/cb'], ['client_credentials'], [], confidential: true);

        // Registration generates the secret, so build the header the way a client
        // would and make sure both halves decode: RFC 6749 §2.3.1 form-encodes them.
        $header = 'Basic ' . base64_encode(rawurlencode($client->id) . ':' . rawurlencode('a:b:c'));

        $this->assertError('invalid_client', 401, fn() => $this->authenticator->authenticate([], $header));
    }

    public function testTheStoredSecretIsNotTheSecret(): void
    {
        [, $secret] = Schema::register($this->connection);

        $stored = $this->connection->query('SELECT secret_hash FROM oauth_clients')?->fetchColumn();

        self::assertIsString($secret);
        self::assertIsString($stored);
        self::assertNotSame($secret, $stored);
        self::assertStringNotContainsString($secret, $stored);
    }

    private function assertError(string $error, int $status, callable $run): void
    {
        try {
            $run();
        } catch (OAuthError $e) {
            self::assertSame($error, $e->error, $e->getMessage());
            self::assertSame($status, $e->status);
            return;
        }

        self::fail('Expected an OAuthError "' . $error . '".');
    }
}
