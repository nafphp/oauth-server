<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use Naf\OAuth\Server\Core\ClientAuthenticator;
use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Store\PdoClients;
use Naf\OAuth\Server\Store\PdoTokens;
use PDO;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/**
 * Changing a client secret without changing the client.
 *
 * The thing that makes this hard is not cryptography, it is that the two sides
 * change at different moments: the new secret exists here before it exists in
 * whatever deployment uses it. A server that cannot hold both for a while is a
 * server on which nobody ever changes a secret.
 */
final class ClientSecretRotationTest extends TestCase
{
    private PDO $connection;
    private PdoClients $clients;
    private ClientAuthenticator $authenticator;

    protected function setUp(): void
    {
        $this->connection    = Schema::migrate(Schema::connect());
        $this->clients       = Schema::clients($this->connection);
        $this->authenticator = new ClientAuthenticator($this->clients, Schema::hasher());
    }

    // ------------------------------------------------------- What stays the same

    public function testTheClientKeepsItsIdentity(): void
    {
        [$client, $old] = Schema::register($this->connection);

        [$rotated, $new] = $this->clients->rotateSecret($client->id, 3600);

        // The entire point: no configuration anywhere has to be edited except the
        // one line holding the secret.
        self::assertSame($client->id, $rotated->id);
        self::assertSame($client->name, $rotated->name);
        self::assertSame($client->redirectUris, $rotated->redirectUris);
        self::assertSame($client->grants, $rotated->grants);
        self::assertSame($client->scopes, $rotated->scopes);
        self::assertNotSame($old, $new);
    }

    public function testWhatWasAlreadyIssuedIsUntouched(): void
    {
        [$client] = Schema::register($this->connection);

        $tokens = (new PdoTokens($this->connection))->issueForClient($client, ['posts.read'], '', 600);

        $this->clients->rotateSecret($client->id, 3600);

        // Rotating a secret is not revoking a client. Somebody halfway through a
        // session has not done anything wrong.
        self::assertNotNull((new PdoTokens($this->connection))->inspect($tokens->accessToken));
    }

    // ----------------------------------------------------------- The overlap

    public function testBothSecretsWorkWhileTheWindowIsOpen(): void
    {
        [$client, $old] = Schema::register($this->connection);

        [, $new] = $this->clients->rotateSecret($client->id, 3600);

        self::assertSame($client->id, $this->authenticate($client->id, (string) $old)->id, 'not yet redeployed');
        self::assertSame($client->id, $this->authenticate($client->id, $new)->id, 'already redeployed');
    }

    public function testTheOldSecretStopsWhenTheWindowLapses(): void
    {
        [$client, $old] = Schema::register($this->connection);

        [, $new] = $this->clients->rotateSecret($client->id, 3600);

        $this->moveDeadline($client->id, time() - 1);

        $this->expectRefusal(fn() => $this->authenticate($client->id, (string) $old));
        self::assertSame($client->id, $this->authenticate($client->id, $new)->id);
    }

    public function testNothingHasToRunForTheWindowToClose(): void
    {
        // It is a deadline, not a state somebody has to tidy up. No sweep, no
        // scheduled command, nothing to forget.
        [$client, $old] = Schema::register($this->connection);
        $this->clients->rotateSecret($client->id, 3600);
        $this->moveDeadline($client->id, time() - 1);

        $stored = $this->clients->find($client->id);

        self::assertNotNull($stored);
        self::assertNotNull($stored->previousSecretHash, 'the row still holds it');
        self::assertFalse($stored->previousSecretIsLive(), 'and it is no longer accepted');
        self::assertNotSame('', (string) $old);
    }

    public function testRotatingNowEndsTheOldSecretAtOnce(): void
    {
        // What a leak calls for. The client stops working until it is redeployed,
        // and that is the intended outcome rather than a side effect.
        [$client, $old] = Schema::register($this->connection);

        [$rotated, $new] = $this->clients->rotateSecret($client->id, 0);

        self::assertNull($rotated->previousSecretHash);
        self::assertNull($rotated->previousSecretExpiresAt);
        $this->expectRefusal(fn() => $this->authenticate($client->id, (string) $old));
        self::assertSame($client->id, $this->authenticate($client->id, $new)->id);
    }

    public function testRotatingTwiceInsideAWindowKeepsOnlyTheOneItJustReplaced(): void
    {
        [$client, $first] = Schema::register($this->connection);

        [, $second] = $this->clients->rotateSecret($client->id, 3600);
        [, $third]  = $this->clients->rotateSecret($client->id, 3600);

        // Two secrets at a time, never three: the first is gone the moment it is
        // no longer the one being replaced.
        $this->expectRefusal(fn() => $this->authenticate($client->id, (string) $first));
        self::assertSame($client->id, $this->authenticate($client->id, $second)->id);
        self::assertSame($client->id, $this->authenticate($client->id, $third)->id);
    }

    public function testAWrongSecretIsStillWrongDuringAWindow(): void
    {
        [$client] = Schema::register($this->connection);
        $this->clients->rotateSecret($client->id, 3600);

        $this->expectRefusal(fn() => $this->authenticate($client->id, 'not-a-secret'));
    }

    // --------------------------------------------------- What cannot be rotated

    public function testAPublicClientHasNoSecretToRotate(): void
    {
        [$client] = Schema::register($this->connection, ['authorization_code'], confidential: false);

        $this->expectException(InvalidArgumentException::class);
        $this->clients->rotateSecret($client->id, 3600);
    }

    public function testAnUnknownClientIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->clients->rotateSecret('nobody', 3600);
    }

    public function testARevokedClientIsNotBroughtBackByRotating(): void
    {
        [$client] = Schema::register($this->connection);
        $this->clients->revoke($client->id);

        $this->expectException(InvalidArgumentException::class);
        $this->clients->rotateSecret($client->id, 3600);
    }

    public function testANegativeOverlapIsRefused(): void
    {
        [$client] = Schema::register($this->connection);

        $this->expectException(InvalidArgumentException::class);
        $this->clients->rotateSecret($client->id, -1);
    }

    // ------------------------------------------------------------- The model

    public function testAClientThatNeverRotatedHasNoWindow(): void
    {
        $client = new Client('id', 'name', 'hash', [], [], []);

        self::assertFalse($client->previousSecretIsLive());
    }

    public function testAWindowIsJudgedAgainstTheMomentItIsAsked(): void
    {
        $client = new Client('id', 'name', 'hash', [], [], [], [], 'old-hash', 1_000);

        self::assertTrue($client->previousSecretIsLive(999));
        self::assertFalse($client->previousSecretIsLive(1_000), 'the deadline is the end, not the last moment');
        self::assertFalse($client->previousSecretIsLive(1_001));
    }

    public function testAHashWithoutADeadlineIsNotAcceptedForever(): void
    {
        $client = new Client('id', 'name', 'hash', [], [], [], [], 'old-hash', null);

        self::assertFalse($client->previousSecretIsLive());
    }

    // --------------------------------------------------------------- Machinery

    private function authenticate(string $clientId, string $secret): Client
    {
        return $this->authenticator->authenticate(
            ['client_id' => $clientId, 'client_secret' => $secret],
            null,
        );
    }

    private function moveDeadline(string $clientId, int $to): void
    {
        $statement = $this->connection->prepare(
            'UPDATE oauth_clients SET previous_secret_expires_at = :t WHERE client_id = :id',
        );
        $statement->execute(['t' => (string) $to, 'id' => $clientId]);
    }

    private function expectRefusal(callable $run): void
    {
        try {
            $run();
            self::fail('Expected the secret to be refused.');
        } catch (OAuthError $e) {
            self::assertSame('invalid_client', $e->error);
        }
    }
}
