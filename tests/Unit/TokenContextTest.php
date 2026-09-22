<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Auth\Exceptions\ForbiddenException;
use Naf\Auth\Exceptions\UnauthenticatedException;
use Naf\Auth\Identity\IdentityInterface;
use Naf\OAuth\Server\Core\ScopePolicy;
use Naf\OAuth\Server\Core\TokenContext;
use Naf\OAuth\Server\Model\TokenRecord;
use PHPUnit\Framework\TestCase;
use Tests\Fixtures\Account;

/**
 * What a bearer token allows — which is the smaller of what the token carries and
 * what the person still holds, and never anything a browser session might say.
 */
final class TokenContextTest extends TestCase
{
    private ScopePolicy $policy;

    protected function setUp(): void
    {
        $this->policy = new ScopePolicy([
            'posts.read'  => ['label' => 'Read posts', 'permission' => 'posts.view'],
            'posts.write' => ['label' => 'Write posts', 'permission' => 'posts.edit'],
        ]);
    }

    // ------------------------------------------------------------ No token

    public function testWithoutATokenThereIsNothing(): void
    {
        $context = $this->context(null);

        self::assertFalse($context->active());
        self::assertNull($context->clientId());
        self::assertSame([], $context->scopes());
        self::assertNull($context->user());
        self::assertFalse($context->can('posts.read'));
    }

    public function testWithoutATokenTheAnswerIs401(): void
    {
        // Not 403, and above all not "whoever the cookie says": there is something
        // to present and it was not presented.
        $this->expectException(UnauthenticatedException::class);

        $this->context(null)->requireScope('posts.read');
    }

    public function testAnInvalidTokenNeverFallsBackToAnybody(): void
    {
        // A request may well carry a session cookie as well. It changes nothing:
        // there is no path from here to auth()'s own state.
        $context = $this->context(null, new Account('42', ['posts.view', 'posts.edit']));

        self::assertNull($context->user());
        self::assertFalse($context->can('posts.read'));
    }

    // --------------------------------------------- Scope and permission both

    public function testAScopeTheTokenCarriesAndThePersonHolds(): void
    {
        $context = $this->context($this->record(['posts.read']), new Account('42', ['posts.view']));

        self::assertTrue($context->hasScope('posts.read'));
        self::assertTrue($context->can('posts.read'));

        $context->requireScope('posts.read');
        $this->addToAssertionCount(1);
    }

    public function testAScopeThePersonNoLongerHoldsStopsWorking(): void
    {
        // Demoted this morning, refused this afternoon — rather than whenever the
        // token happens to expire.
        $context = $this->context($this->record(['posts.write']), new Account('42', ['posts.view']));

        self::assertTrue($context->hasScope('posts.write'), 'the token still says so');
        self::assertFalse($context->can('posts.write'), 'the person does not');

        $this->expectException(ForbiddenException::class);
        $context->requireScope('posts.write');
    }

    public function testAReadTokenStaysReadOnlyInAnAdministratorsHands(): void
    {
        $context = $this->context($this->record(['posts.read']), new Account('42', ['posts.view', 'posts.edit']));

        self::assertTrue($context->can('posts.read'));
        self::assertFalse($context->can('posts.write'), 'the permission is there, the scope is not');
    }

    public function testTheScopeNameIsNotThePermissionName(): void
    {
        // posts.write requires posts.edit; holding a permission called
        // "posts.write" is not the same thing.
        $context = $this->context($this->record(['posts.write']), new Account('42', ['posts.write']));

        self::assertFalse($context->can('posts.write'));
    }

    public function testAVanishedOrSuspendedAccountLosesAccess(): void
    {
        $context = $this->context($this->record(['posts.read']), null);

        self::assertTrue($context->active(), 'the token itself is still live');
        self::assertNull($context->user());
        self::assertFalse($context->can('posts.read'));
    }

    // --------------------------------------------------------- Applications

    public function testAnApplicationTokenStandsForNobody(): void
    {
        $context = $this->context(new TokenRecord('client-1', null, null, ['posts.read'], '', time() + 60));

        self::assertTrue($context->isApplication());
        self::assertNull($context->user());

        // Its registration is the whole answer; there are no personal permissions
        // to also satisfy, and no user is invented to carry them.
        self::assertTrue($context->can('posts.read'));
        self::assertFalse($context->can('posts.write'));
    }

    public function testSeveralScopesMeanAllOfThem(): void
    {
        $context = $this->context($this->record(['posts.read', 'posts.write']), new Account('42', ['posts.view']));

        self::assertFalse($context->can('posts.read', 'posts.write'));
        self::assertTrue($context->can('posts.read'));
    }

    // --------------------------------------------------------------- Machinery

    /** @param list<string> $scopes */
    private function record(array $scopes): TokenRecord
    {
        return new TokenRecord('client-1', 'database', '42', $scopes, '', time() + 60);
    }

    private function context(?TokenRecord $record, ?IdentityInterface $user = null): TokenContext
    {
        return new TokenContext(
            $record,
            $this->policy,
            static fn(string $provider, string $id): ?IdentityInterface => $user,
        );
    }
}
