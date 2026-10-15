<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Core\ResourceServer;
use Naf\OAuth\Server\Store\TokenStoreInterface;
use Nyholm\Psr7\ServerRequest;
use Tests\CommandTestCase;

use function Naf\app;
use function Naf\json;
use function Naf\OAuth\Server\token;
use function Naf\route;

final class ResourceRequestIsolationTest extends CommandTestCase
{
    public function testTokenHelperUsesEachSuppliedRequestOnOneApplication(): void
    {
        if (!method_exists(app(), 'handle')) {
            self::markTestSkipped('Supplied-request integration requires naf/framework >= 0.2.12.');
        }
        $this->healthy(withClient: false);
        [$firstClient]  = $this->register(grants: ['client_credentials']);
        [$secondClient] = $this->register(name: 'Second client', grants: ['client_credentials']);
        $tokens         = app()->container()->get(TokenStoreInterface::class);
        $first          = $tokens->issueForClient($firstClient, ['posts.read'], '', 60);
        $second         = $tokens->issueForClient($secondClient, ['posts.read'], '', 60);
        route()->add('GET', '/audit-token-isolation', static function () {
            token()->requireScope('posts.read');

            return json(['client' => token()->clientId()]);
        }, 'audit.token.isolation');

        $request  = new ServerRequest('GET', 'https://api.example.test/audit-token-isolation');
        $response = app()->handle($request->withHeader('Authorization', 'Bearer ' . $first->accessToken));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame($firstClient->id, json_decode((string) $response->getBody(), true)['client']);
        $server = app()->container()->get(ResourceServer::class);

        self::assertSame(401, app()->handle($request)->getStatusCode());
        self::assertSame(401, app()->handle($request->withHeader('Authorization', 'Bearer invalid'))->getStatusCode());
        $response = app()->handle($request->withHeader('Authorization', 'Bearer ' . $second->accessToken));
        self::assertSame(200, $response->getStatusCode());
        self::assertSame($secondClient->id, json_decode((string) $response->getBody(), true)['client']);
        self::assertSame($server, app()->container()->get(ResourceServer::class));
    }
}
