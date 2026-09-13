<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use NixPHP\OAuth\Server\Exception\OAuthError;
use NixPHP\OAuth\Server\Model\Client;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Schema;

/** What a registration allows — and the shortcuts it refuses to take. */
final class ClientTest extends TestCase
{
    private const string URI = 'https://intranet.example.test/callback';

    // ------------------------------------------------------- Redirect URIs

    public function testTheRegisteredUriIsAccepted(): void
    {
        self::assertSame(self::URI, $this->client()->redirectUri(self::URI));
    }

    public function testOnlyTheRegisteredUriIsAccepted(): void
    {
        $client = $this->client();

        // Every one of these has been somebody's account-takeover bug.
        foreach ([
            'https://intranet.example.test/callback/',
            'https://intranet.example.test/callback?x=1',
            'https://intranet.example.test/callback/../evil',
            'https://intranet.example.test.evil.test/callback',
            'https://evil.test/callback',
            'https://intranet.example.test/CALLBACK',
            'http://intranet.example.test/callback',
        ] as $attempt) {
            try {
                $client->redirectUri($attempt);
                self::fail('Accepted: ' . $attempt);
            } catch (OAuthError $e) {
                self::assertSame('invalid_request', $e->error);
                self::assertFalse($e->redirectable, 'an unverified URI is never redirected to');
            }
        }
    }

    public function testASoleRegisteredUriNeedsNoNaming(): void
    {
        self::assertSame(self::URI, $this->client()->redirectUri(null));
    }

    public function testWithSeveralUrisTheRequestHasToChoose(): void
    {
        $client = $this->client(uris: [self::URI, 'https://intranet.example.test/other']);

        $this->assertError('invalid_request', static fn() => $client->redirectUri(null));
        self::assertSame('https://intranet.example.test/other', $client->redirectUri('https://intranet.example.test/other'));
    }

    // -------------------------------------------------------------- Scopes

    public function testAskingForNothingGetsWhatTheClientMayHave(): void
    {
        self::assertSame(['posts.read', 'posts.write'], $this->client()->grantableScopes([]));
    }

    public function testAskingForLessGetsLess(): void
    {
        self::assertSame(['posts.read'], $this->client()->grantableScopes(['posts.read']));
    }

    public function testAskingForMoreIsRefusedRatherThanTrimmed(): void
    {
        // Quietly trimming would leave a client believing it holds a scope it does
        // not, and failing somewhere further away.
        $this->assertError('invalid_scope', fn() => $this->client()->grantableScopes(['posts.read', 'users.delete']));
    }

    // ---------------------------------------------------------- Registering

    public function testAnInsecureRedirectUriIsNotRegistered(): void
    {
        $clients = Schema::clients(Schema::migrate(Schema::connect()));

        $this->expectException(InvalidArgumentException::class);

        $clients->register('Acme', ['http://intranet.example.test/cb'], ['authorization_code'], [], confidential: true);
    }

    public function testLoopbackIsAllowedForNativeApplications(): void
    {
        $clients = Schema::clients(Schema::migrate(Schema::connect()));

        [$client] = $clients->register('Acme CLI', ['http://127.0.0.1:8765/cb'], ['authorization_code'], [], confidential: false);

        self::assertSame(['http://127.0.0.1:8765/cb'], $client->redirectUris);
    }

    public function testAPublicClientCannotBeGivenIntrospection(): void
    {
        $clients = Schema::clients(Schema::migrate(Schema::connect()));

        // A client id is not a secret: it travels in every authorize URL.
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/confidential/');

        $clients->register('Snoop', [], ['introspection'], [], confidential: false);
    }

    public function testARevokedClientIsNoLongerFound(): void
    {
        $connection = Schema::migrate(Schema::connect());
        $clients    = Schema::clients($connection);
        [$client]   = $clients->register('Acme', [self::URI], ['authorization_code'], [], confidential: true);

        self::assertNotNull($clients->find($client->id));

        $clients->revoke($client->id);

        self::assertNull($clients->find($client->id));
        self::assertSame([], $clients->all());
    }

    // --------------------------------------------------------------- Machinery

    /** @param list<string> $uris */
    private function client(array $uris = [self::URI]): Client
    {
        return new Client(
            id: 'client-1',
            name: 'Acme Intranet',
            secretHash: null,
            redirectUris: $uris,
            grants: ['authorization_code', 'refresh_token'],
            scopes: ['posts.read', 'posts.write'],
        );
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
