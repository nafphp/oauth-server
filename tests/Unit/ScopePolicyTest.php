<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Core\ScopePolicy;
use Naf\OAuth\Server\Exception\ConfigurationException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use stdClass;

final class ScopePolicyTest extends TestCase
{
    public static function invalidPermissions(): iterable
    {
        foreach ([false, true, 0, 1, '', [], new stdClass(), " \t\r\n"] as $index => $value) {
            yield (string) $index => [$value];
        }
    }

    #[DataProvider('invalidPermissions')]
    public function testInvalidPermissionsAreConfigurationErrorsBeforeAnyGrant(mixed $permission): void
    {
        $this->expectException(ConfigurationException::class);
        $this->expectExceptionMessage('notes:delete');
        new ScopePolicy(['notes:delete' => ['permission' => $permission]]);
    }

    public function testMissingNullAndExplicitPermissionsHaveDistinctMeanings(): void
    {
        $policy = new ScopePolicy([
            'notes:read'   => ['label' => 'Read notes'],
            'notes:delete' => ['permission' => 'notes.delete'],
            'mcp:service'  => ['permission' => null],
        ]);
        self::assertSame('notes:read', $policy->permission('notes:read'));
        self::assertSame('notes.delete', $policy->permission('notes:delete'));
        self::assertNull($policy->permission('mcp:service'));
        self::assertNull($policy->permission('openid'));
    }
}
