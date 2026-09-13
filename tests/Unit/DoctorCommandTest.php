<?php

declare(strict_types=1);

namespace Tests\Unit;

use NixPHP\OAuth\Server\Commands\DoctorCommand;
use NixPHP\OAuth\Server\Store\ClientStoreInterface;
use Tests\CommandTestCase;
use function NixPHP\app;

/**
 * What "nix oauth:server:doctor" says about an installation.
 *
 * A sign-in service that is almost set up is worse than one that is plainly not:
 * the failures land in front of people trying to sign in, mid-redirect, where
 * nothing they can do will help. This command exists to move those failures
 * earlier, which only works if what it says is exact.
 */
final class DoctorCommandTest extends CommandTestCase
{
    public function testAHealthySetupSaysSoAndSucceeds(): void
    {
        $this->healthy();

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Ready to answer.', $result->output);
    }

    public function testItNamesTheIssuerAndTheService(): void
    {
        $this->healthy();

        $result = $this->execute(new DoctorCommand());

        // Relying parties check the issuer, and people read the name on the
        // consent screen. Both are stated, never guessed.
        self::assertStringContainsString('https://id.example.test', (string) $result->line('issuer'));
        self::assertStringContainsString('Probe ID', (string) $result->line('service name'));
    }

    public function testAMissingServiceNameIsAProblem(): void
    {
        $this->healthy(['name' => null]);

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('MISSING', (string) $result->line('service name'));
    }

    public function testAMissingIssuerIsAProblem(): void
    {
        $this->database();
        $this->configure(['name' => 'Probe ID', 'login_route' => '/login'], publicUrl: null);
        $this->boot();
        $this->register();

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('MISSING', (string) $result->line('issuer'));
    }

    public function testAnUnmigratedDatabaseNamesTheTablesThatAreMissing(): void
    {
        $this->database(migrated: false);
        $this->configure(['name' => 'Probe ID', 'login_route' => '/login']);
        $this->boot();

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('missing', (string) $result->line('oauth_clients'));
        self::assertStringContainsString('db:migrate up', $result->output);
    }

    public function testTheConnectionItWillActuallyUseIsReported(): void
    {
        $this->healthy();

        self::assertStringContainsString('sqlite', (string) $this->execute(new DoctorCommand())->line('connection'));
    }

    // ------------------------------------------------------------- Signing keys

    public function testWithoutASigningKeyItIsAnOAuth2ServerAndSaysSo(): void
    {
        // Not a fault. An OAuth2 server is a complete thing to be, and reporting
        // a missing key as a problem would push people into turning on OpenID
        // Connect because a tool told them to.
        $this->healthy();

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('off', (string) $result->line('OpenID Connect'));
    }

    public function testASigningKeyTurnsOpenIdConnectOn(): void
    {
        $this->healthy();
        app()->container()->get(\NixPHP\OAuth\Server\Store\KeyStoreInterface::class)->generate();

        $result = $this->execute(new DoctorCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('on', (string) $result->line('OpenID Connect'));
        self::assertStringContainsString('1 published key', (string) $result->line('OpenID Connect'));
    }

    // -------------------------------------------------------------- The rest

    public function testItListsTheScopesThisServerOffers(): void
    {
        $this->healthy(['scopes' => ['posts.read' => 'Read posts', 'posts.write' => 'Write posts']]);

        $scopes = (string) $this->execute(new DoctorCommand())->line('scopes');

        self::assertStringContainsString('posts.read', $scopes);
        self::assertStringContainsString('posts.write', $scopes);
    }

    public function testWithoutALoginRouteItSaysWhereToSetOne(): void
    {
        $this->healthy(['login_route' => null]);

        $result = $this->execute(new DoctorCommand());

        $this->assertFailed($result);
        self::assertStringContainsString('oauth_server:login_route', (string) $result->line('login route'));
    }

    public function testItCountsClientsWithoutEverPrintingOne(): void
    {
        $this->healthy(withClient: false);

        [, $secret] = $this->register();

        $result = $this->execute(new DoctorCommand());

        self::assertStringContainsString('1', (string) $result->line('registered clients'));
        self::assertStringNotContainsString((string) $secret, $result->output);
    }
}
