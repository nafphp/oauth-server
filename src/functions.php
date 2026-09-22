<?php

declare(strict_types=1);

namespace Naf\OAuth\Server;

use Naf\OAuth\Server\Core\ResourceServer;
use Naf\OAuth\Server\Core\TokenContext;

use function Naf\app;

/** What the bearer token on this request allows. Never the browser session. */
function token(): TokenContext
{
    return app()->container()->get(ResourceServer::class)->context();
}
