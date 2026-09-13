<?php

declare(strict_types=1);

return [
    /*
     * The protocol endpoints are called by programs, not by browsers following a
     * link: they carry no session to ride on and no form to put a token in, so a
     * CSRF check there refuses legitimate requests and protects nothing.
     *
     * A map rather than a list, so that several plugins can contribute without
     * overwriting one another — and so an application can switch one back on.
     *
     * /oauth/authorize is deliberately absent: approving is a state-changing POST
     * made by a person, and it keeps its CSRF token like every other form.
     */
    'csrf_exempt_routes' => [
        'oauth.token'      => true,
        'oauth.revoke'     => true,
        'oauth.introspect' => true,
        'oauth.userinfo.post' => true,

        // The consent form carries its own token, bound to the one request it
        // belongs to — see AuthorizeController::formToken(). The session-wide
        // token cannot do that job: a second form invalidates the first.
        'oauth.authorize.decide' => true,
    ],

    /*
     * The public base URL of this application. It becomes the OIDC issuer once
     * that ships, so it has to stay stable for the life of the service.
     *
     * Shared with naf/oauth-client, which derives its redirect URIs from it.
     */
    'public_url' => null,

    'oauth_server' => [
        /*
         * What this sign-in service is called, wherever a person can see it.
         *
         * There is no default on purpose: a service that ships somebody else's
         * name is worse than one that refuses to start.
         *
         * Display only. It never reaches an issuer, a client id, a redirect URI
         * or a subject, and OIDC discovery defines no field to publish it in —
         * what a relying party shows is whatever its own configuration says.
         */
        'name' => null,

        // Ship /oauth/authorize, /oauth/token, /oauth/revoke and /oauth/introspect.
        'routes' => true,

        /*
         * Which API scopes this server offers, and what each one means.
         *
         *   'posts.write' => ['label' => 'Write posts', 'permission' => 'posts.edit'],
         *
         * A scope is granted only to somebody who also holds its permission, both
         * when the token is issued and every time it is used. Leave 'permission'
         * out and the scope name is the permission; give a plain string instead of
         * an array and it is the label.
         */
        'scopes' => [],

        // Where to send somebody who is not signed in yet. Derived from a route
        // named "login" when there is one.
        'login_route' => null,

        /*
         * What this application's own API is called, when a token has to say which
         * API it is for.
         *
         * The empty default is the ordinary case: one server, one API, and tokens
         * carry no target. Set it only when this installation serves an API that
         * clients name explicitly with the "resource" parameter — and then a token
         * granted for anything else is refused here.
         */
        'audience' => '',

        // Lifetimes, in seconds.
        'access_token_ttl'  => 3600,
        'refresh_token_ttl' => 2592000,
        'id_token_ttl'      => 3600,
        'code_ttl'          => 60,
        'consent_ttl'       => 600,

        /*
         * Where the ID token signing keys live. Null resolves to
         * BASE_PATH/storage/oauth/keys.
         *
         * Created once with "nix oauth:keys:generate" and kept. Until one exists
         * this is an OAuth2 server: no ID tokens, and the discovery document says
         * so rather than advertising something it cannot answer.
         */
        'key_path' => null,

        /*
         * Anything this server may say about a person beyond their profile.
         *
         * Usually nothing: a model implementing UserInterface already says what
         * may be shown about it through getProfile(), and that is what gets
         * released. Configure this only for claims the profile does not cover:
         *
         *   'claims' => static fn(User $user): array => ['locale' => $user->locale],
         *
         * It adds to the profile rather than replacing it, and what it returns is
         * still filtered by the scopes that were actually granted — anything
         * OpenID Connect defines no scope for is dropped.
         */
        'claims' => null,
    ],
];
