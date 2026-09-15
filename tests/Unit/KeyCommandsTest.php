<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\CLI\Support\CommandRegistry;
use Naf\OAuth\Server\Commands\KeysGenerateCommand;
use Naf\OAuth\Server\Commands\KeysPruneCommand;
use Naf\OAuth\Server\Commands\SetupCommand;
use Naf\OAuth\Server\Store\KeyStoreInterface;
use Tests\CommandTestCase;

use function Naf\app;

/**
 * Setting the server up, and rotating what it signs with.
 *
 * Rotation is the reason a key store has two questions rather than one: what
 * signs now, and what still has to be published. A command that got the second
 * wrong would invalidate tokens nobody has finished using, and it would do it
 * quietly.
 */
final class KeyCommandsTest extends CommandTestCase
{
    // ------------------------------------------------------------------- Setup

    public function testSetupCreatesTheFirstSigningKey(): void
    {
        $this->healthy();

        $result = $this->execute(new SetupCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Signing key created', $result->output);
        self::assertTrue($this->keys()->has());
    }

    public function testSetupLeavesAnExistingKeyAlone(): void
    {
        $this->healthy();
        $existing = $this->keys()->generate();

        $result = $this->execute(new SetupCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('already present', $result->output);
        self::assertSame($existing->id, $this->keys()->active()->id, 'a second key here would retire the first');
    }

    public function testEveryCommandSetupTellsSomebodyToRunExists(): void
    {
        // The instructions are the first thing a new installation follows, and a
        // typo in one is indistinguishable from a broken install to whoever is
        // reading. This caught "db:migrate up up".
        $this->healthy();

        $output   = $this->execute(new SetupCommand())->output;
        $registry = app()->container()->get(CommandRegistry::class);

        preg_match_all('/naf ([a-z0-9:._-]+(?: [a-z0-9:._-]+)*)/', $output, $matches);

        self::assertNotSame([], $matches[1], 'the instructions name no commands at all');

        foreach ($matches[1] as $invocation) {
            $words = explode(' ', $invocation);
            $name  = array_shift($words);

            // Anything this plugin ships has to be a command it registers.
            if (str_starts_with($name, 'oauth:')) {
                self::assertNotNull($registry->get($name), 'unknown command: ' . $name);
            }

            self::assertSame(
                array_values(array_unique($words)),
                $words,
                'repeated argument in: naf ' . $invocation,
            );
        }
    }

    // -------------------------------------------------------------- Generating

    public function testTheFirstKeyIsCreatedRatherThanRotatedTo(): void
    {
        $this->healthy();

        $result = $this->execute(new KeysGenerateCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Signing key created', $result->output);
        self::assertSame('1', $result->value('Published keys'));
    }

    public function testGeneratingAgainRotatesAndKeepsThePreviousOnePublished(): void
    {
        $this->healthy();
        $first = $this->keys()->generate();

        $result = $this->execute(new KeysGenerateCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Rotated', $result->output);
        self::assertSame('2', $result->value('Published keys'));
        self::assertNotSame($first->id, $this->keys()->active()->id);

        // Tokens signed a second ago still have to verify, so it is said out loud.
        self::assertStringContainsString('still verify', $result->output);
        self::assertStringContainsString('oauth:keys:prune', $result->output);
    }

    // ----------------------------------------------------------------- Pruning

    public function testPruningRefusesAnAgeShorterThanAnIdTokenLives(): void
    {
        // Removing a key younger than the tokens it signed is how a rotation
        // turns into an outage, so the command will not do it on request.
        $this->healthy(['id_token_ttl' => 3600]);

        $result = $this->execute(new KeysPruneCommand(), ['--older-than=60']);

        $this->assertFailed($result);
        self::assertStringContainsString('still in use', $result->output);
    }

    public function testPruningSaysWhenThereIsNothingToRemove(): void
    {
        $this->healthy();
        $this->keys()->generate();

        $result = $this->execute(new KeysPruneCommand());

        $this->assertSucceeded($result);
        self::assertStringContainsString('Nothing to remove', $result->output);
    }

    public function testPruningNeverRemovesTheKeyThatSigns(): void
    {
        $this->healthy();
        $active = $this->keys()->generate();

        $this->execute(new KeysPruneCommand(), ['--older-than=3600']);

        self::assertSame($active->id, $this->keys()->active()->id);
    }

    public function testARetiredKeyGoesOnceItsTokensCouldHaveExpired(): void
    {
        $this->healthy();
        $retired = $this->keys()->generate();
        $this->keys()->generate();

        // Retirement is when it stopped signing, not when it was made. Age that
        // moment rather than waiting out an ID token lifetime.
        $this->retireLongAgo($retired->id);

        $result = $this->execute(new KeysPruneCommand(), ['--older-than=7200']);

        $this->assertSucceeded($result);
        self::assertStringContainsString($retired->id, $result->output);
        self::assertCount(1, $this->keys()->all());
    }

    // --------------------------------------------------------------- Machinery

    private function keys(): KeyStoreInterface
    {
        return app()->container()->get(KeyStoreInterface::class);
    }

    private function retireLongAgo(string $id): void
    {
        file_put_contents($this->keyPath . '/' . $id . '.pem.retired', (string) (time() - 100_000));
    }
}
