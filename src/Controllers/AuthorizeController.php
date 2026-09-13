<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Controllers;

use Naf\Core\Route;
use Naf\OAuth\Server\Support\Views;
use Naf\OAuth\Server\Core\Authorization;
use Naf\OAuth\Server\Exception\OAuthError;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use function Naf\app;
use function Naf\Auth\auth;
use function Naf\config;
use function Naf\param;
use function Naf\redirect;
use function Naf\response;

/**
 * Where a person is asked whether an application may act for them.
 *
 * The sign-in itself is not reinvented here: whoever is not signed in is sent to
 * the application's own login and comes back. What this endpoint owns is the
 * asking, and the rule that the answer belongs to the request the server
 * validated — never to what the browser posts back.
 */
final class AuthorizeController
{
    public function show(): ResponseInterface
    {
        $request = self::request();

        if (!auth()->check()) {
            return redirect(self::loginRoute() . '?next=' . rawurlencode(self::currentPath($request)));
        }

        try {
            $consent = self::authorization()->begin(
                $request->getQueryParams(),
                session_id(),
                (string) auth()->providerName(),
                (string) auth()->id(),
            );
        } catch (OAuthError $e) {
            return self::fail($e);
        }

        return response(Views::render('oauth.consent', [
            'consent' => $consent,
            'service' => (string) config('oauth_server:name'),

            // Bound to this request and this browser rather than to one global
            // token, so that opening a second consent form does not invalidate
            // the first. Nothing is stored for it: the value is derived, and the
            // session id it is derived from never leaves the server.
            'csrf'    => self::formToken($consent->requestId),
        ]));
    }

    public function decide(): ResponseInterface
    {
        // The CSRF token on this form is checked by naf/form before we get here;
        // this endpoint is deliberately not among the exempt ones.
        auth()->requireLogin();

        $requestId = param()->get('request_id');

        if (!is_string($requestId) || $requestId === '') {
            return self::fail(OAuthError::refuse('invalid_request', 'That form did not name a request.'));
        }

        $token = param()->get('_csrf');

        if (!is_string($token) || !hash_equals(self::formToken($requestId), $token)) {
            return self::fail(OAuthError::refuse('invalid_request', 'That form did not come from here.'));
        }

        $authorization = self::authorization();
        $arguments     = [$requestId, session_id(), (string) auth()->providerName(), (string) auth()->id()];

        try {
            return redirect(param()->get('approve') !== null
                ? $authorization->approve(...$arguments)
                : $authorization->deny(...$arguments));
        } catch (OAuthError $e) {
            return self::fail($e);
        }
    }

    // ---------------------------------------------------------------- Internals

    /**
     * An error goes back to the client only once the request has established a
     * redirect URI that belongs to it. Everything before that point is answered
     * here, because sending it onwards would mean redirecting to an address
     * nobody has vouched for.
     */
    private static function fail(OAuthError $e): ResponseInterface
    {
        $target = $e->redirectTarget();

        if ($target !== null) {
            return redirect($target);
        }

        return response(Views::render('oauth.error', [
            'error'       => $e->error,
            'description' => $e->description,
            'service'     => (string) config('oauth_server:name'),
        ]), $e->status);
    }

    /**
     * A CSRF token for one consent form.
     *
     * Derived from the request it belongs to and keyed by the session, so two
     * consent forms open at once both keep working — which a single session-wide
     * token cannot manage, because issuing the second one invalidates the first.
     */
    private static function formToken(string $requestId): string
    {
        return hash_hmac('sha256', $requestId, session_id());
    }

    private static function authorization(): Authorization
    {
        return app()->container()->get(Authorization::class);
    }

    private static function request(): ServerRequestInterface
    {
        return app()->container()->get(ServerRequestInterface::class);
    }

    private static function currentPath(ServerRequestInterface $request): string
    {
        $query = $request->getUri()->getQuery();

        return $request->getUri()->getPath() . ($query === '' ? '' : '?' . $query);
    }

    /**
     * The application's own login. Configured, or derived when exactly one route
     * is called "login" — and an error rather than a guess when it is neither.
     */
    private static function loginRoute(): string
    {
        $configured = config('oauth_server:login_route');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        $routes = app()->container()->get(Route::class)->all();

        if (isset($routes['login'])) {
            return (string) $routes['login']['path'];
        }

        throw new \LogicException(
            'oauth_server:login_route is required: this application has no route named "login" to send people to.'
        );
    }
}
