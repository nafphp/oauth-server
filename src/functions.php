<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server;

use NixPHP\OAuth\Server\Core\ResourceServer;
use NixPHP\OAuth\Server\Core\TokenContext;
use function NixPHP\app;

/** What the bearer token on this request allows. Never the browser session. */
function token(): TokenContext
{
    return app()->container()->get(ResourceServer::class)->context();
}
