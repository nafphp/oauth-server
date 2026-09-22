<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Commands\ClientCreateCommand;
use Naf\OAuth\Server\Commands\ClientListCommand;
use Naf\OAuth\Server\Commands\ClientRotateSecretCommand;
use Naf\OAuth\Server\Core\ClientAuthenticator;
use Naf\OAuth\Server\Exception\OAuthError;
use Naf\OAuth\Server\Store\ClientStoreInterface;
use Tests\CommandTestCase;

use function Naf\app;

/**
 * Registering an application, listing what is registered, and changing a secret.
 *
 * These are the commands an administrator runs, so the value printed has to be
 * the value that works — the secret exists nowhere else afterwards, and a wrong
 * one is only discovered by whoever tries to use it.
 */
final class ClientCommandsTest extends CommandTestCase
{
    // ---------------------------------------------------------------- Creating

    public function testCreatingPrintsAnIdAndASecretThatActuallyWork(): void
    {
        $this->healthy(withClient: false);

        $result = $this->execute(new ClientCreateCommand(), [
            'Acme Intranet',
            '--redirect=https://intranet.example.test/callback',
            '--scope=posts.read',
        ]);

        $this->assertSucceeded($result);
        self::assertStringContainsString('cannot be shown again', $result->output);

        // The printed pair is the pair the server will accept. Nothing else here
        // can tell us that, because the secret is a hash from now on.
        [$id, $secret] = [$result->value('Client ID'), $result->value('Client secret')];

        $authenticated = app()->container()->get(ClientAuthenticator::class)
            ->authenticate(['client_id' => $id, 'client_secret' => $secret], null);

        self::assertSame($id, $authenticated->id);
        self::assertSame('Acme Intranet', $authenticated->name);
    }

    public function testCreatingWithoutANameSaysHowToCallIt(): void
    {
        $this->healthy(withClient: false);

        $result = $this->execute(new ClientCreateCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('oauth:client:create', $result->output);
        self::assertSame([], app()->container()->get(ClientStoreInterface::class)->all());
    }

    public function testAPublicClientGetsNoSecretAndIsToldWhyNot(): void
    {
        $this->healthy(withClient: false);

        $result = $this->execute(new ClientCreateCommand(), [
            'Mobile App',
            '--redirect=https://app.example.test/callback',
            '--public',
        ]);

        $this->assertSucceeded($result);
        self::assertSame('', $result->value('Client secret'));
        self::assertStringContainsString('PKCE', $result->output);
    }

    public function testARedirectUriThatIsNotHttpsIsRefusedBeforeAnythingIsStored(): void
    {
        $this->healthy(withClient: false);

        $result = $this->execute(new ClientCreateCommand(), ['Acme', '--redirect=http://intranet.example.test/cb']);

        $this->assertFailed($result);
        self::assertSame([], app()->container()->get(ClientStoreInterface::class)->all(), 'nothing half-registered');
    }

    // ----------------------------------------------------------------- Listing

    public function testListingSaysSoWhenNothingIsRegistered(): void
    {
        $this->healthy(withClient: false);

        $result = $this->execute(new ClientListCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('No applications are registered yet.', $result->output);
    }

    public function testListingShowsWhatEachClientMayDo(): void
    {
        $this->healthy();

        $result = $this->execute(new ClientListCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Acme Intranet', $result->output);
        self::assertSame('confidential', $result->value('Kind'));
        self::assertStringContainsString('authorization_code', $result->value('Grants'));
        self::assertStringContainsString('https://intranet.example.test/callback', $result->value('Redirect URIs'));
    }

    public function testListingShowsWhenASecretIsStillBeingRotated(): void
    {
        // The window closes on its own and nothing runs when it does, so a client
        // whose new secret was never deployed simply stops working one day. This
        // is where somebody would look for it.
        $this->healthy(withClient: false);
        [$client] = $this->register();

        self::assertSame('', $this->execute(new ClientListCommand())->value('Rotating'));

        app()->container()->get(ClientStoreInterface::class)->rotateSecret($client->id, 3600);

        $rotating = $this->execute(new ClientListCommand())->value('Rotating');

        self::assertStringContainsString('previous secret accepted until', $rotating);

        // The printed moment is the deadline, not "some time today": an overlap
        // that starts an hour before midnight ends tomorrow.
        $deadline = strtotime(trim(str_replace('previous secret accepted until', '', $rotating)));

        self::assertIsInt($deadline);
        self::assertEqualsWithDelta(time() + 3600, $deadline, 5);
    }

    public function testAFinishedRotationIsNotStillAdvertised(): void
    {
        $this->healthy(withClient: false);
        [$client] = $this->register();

        app()->container()->get(ClientStoreInterface::class)->rotateSecret($client->id, 0);

        self::assertSame('', $this->execute(new ClientListCommand())->value('Rotating'));
    }

    public function testListingNeverShowsASecret(): void
    {
        $this->healthy(withClient: false);
        [, $secret] = $this->register();

        self::assertStringNotContainsString((string) $secret, $this->execute(new ClientListCommand())->output);
    }

    // ---------------------------------------------------------------- Rotating

    public function testRotatingPrintsAWorkingSecretAndKeepsTheId(): void
    {
        $this->healthy(withClient: false);
        [$client, $old] = $this->register();

        $result = $this->execute(new ClientRotateSecretCommand(), [$client->id]);

        $this->assertSucceeded($result);
        self::assertStringContainsString($client->id, $result->value('Client ID'));
        self::assertStringContainsString('unchanged', $result->value('Client ID'));

        $authenticator = app()->container()->get(ClientAuthenticator::class);
        $new           = $result->value('New secret');

        self::assertNotSame($old, $new);
        self::assertSame($client->id, $authenticator->authenticate(
            ['client_id' => $client->id, 'client_secret' => $new],
            null,
        )->id);

        // And the old one still works, which is the entire reason for the window.
        self::assertSame($client->id, $authenticator->authenticate(
            ['client_id' => $client->id, 'client_secret' => (string) $old],
            null,
        )->id);
    }

    public function testRotatingNamesTheDeadlineSomebodyHasToDeployBefore(): void
    {
        $this->healthy(withClient: false);
        [$client] = $this->register();

        $result = $this->execute(new ClientRotateSecretCommand(), [$client->id, '--overlap=3600']);

        self::assertStringContainsString('3600s', $result->output);
        self::assertStringContainsString('Deploy the new one before then', $result->output);
    }

    public function testRotatingNowSaysTheOldSecretIsAlreadyGone(): void
    {
        $this->healthy(withClient: false);
        [$client, $old] = $this->register();

        $result = $this->execute(new ClientRotateSecretCommand(), [$client->id, '--now']);

        $this->assertSucceeded($result);
        self::assertStringContainsString('stopped working just now', $result->output);

        $this->expectException(OAuthError::class);
        app()->container()->get(ClientAuthenticator::class)
            ->authenticate(['client_id' => $client->id, 'client_secret' => (string) $old], null);
    }

    public function testAnOverlapAndNowTogetherIsAContradiction(): void
    {
        $this->healthy(withClient: false);
        [$client] = $this->register();

        $result = $this->execute(new ClientRotateSecretCommand(), [$client->id, '--now', '--overlap=60']);

        $this->assertFailed($result);
        self::assertStringContainsString('not both', $result->output);
    }

    public function testAnOverlapThatIsNotANumberIsRefused(): void
    {
        $this->healthy(withClient: false);
        [$client] = $this->register();

        $this->assertFailed($this->execute(new ClientRotateSecretCommand(), [$client->id, '--overlap=soon']));
    }

    public function testRotatingAnUnknownClientFails(): void
    {
        $this->healthy(withClient: false);

        $this->assertFailed($this->execute(new ClientRotateSecretCommand(), ['nobody']));
    }

    public function testRotatingAPublicClientExplainsWhyThereIsNothingToRotate(): void
    {
        $this->healthy(withClient: false);
        [$client] = $this->register(confidential: false, grants: ['authorization_code']);

        $result = $this->execute(new ClientRotateSecretCommand(), [$client->id]);

        $this->assertFailed($result);
        self::assertStringContainsString('PKCE', $result->output);
    }

    public function testRotatingWithoutNamingAClientSaysHow(): void
    {
        $this->healthy(withClient: false);

        $result = $this->execute(new ClientRotateSecretCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('oauth:client:rotate-secret', $result->output);
    }
}
