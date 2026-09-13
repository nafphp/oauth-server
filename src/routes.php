<?php

declare(strict_types=1);

use NixPHP\OAuth\Server\Controllers\{AuthorizeController, OpenIdController, TokenController};
use function NixPHP\config;
use function NixPHP\route;

// Turn these off with oauth_server:routes => false to own the URLs yourself.
// The endpoints behind them stay available through the container.
if (config('oauth_server:routes', true) !== false) {
    route()->add('GET', '/oauth/authorize', [AuthorizeController::class, 'show'], 'oauth.authorize');
    route()->add('POST', '/oauth/authorize', [AuthorizeController::class, 'decide'], 'oauth.authorize.decide');
    route()->add('POST', '/oauth/token', [TokenController::class, 'issue'], 'oauth.token');
    route()->add('POST', '/oauth/revoke', [TokenController::class, 'revoke'], 'oauth.revoke');
    route()->add('POST', '/oauth/introspect', [TokenController::class, 'introspect'], 'oauth.introspect');

    // OpenID Connect. The discovery document only advertises these once a signing
    // key exists, so an installation that never generated one simply never points
    // anybody at them.
    route()->add('GET', '/oauth/userinfo', [OpenIdController::class, 'userInfo'], 'oauth.userinfo');
    route()->add('POST', '/oauth/userinfo', [OpenIdController::class, 'userInfo'], 'oauth.userinfo.post');
    route()->add('GET', '/.well-known/openid-configuration', [OpenIdController::class, 'configuration'], 'oauth.discovery');
    route()->add('GET', '/.well-known/jwks.json', [OpenIdController::class, 'keys'], 'oauth.jwks');
}
