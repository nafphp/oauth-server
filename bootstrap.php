<?php

declare(strict_types=1);

use NixPHP\Auth\Support\PasswordHasher;
use NixPHP\CLI\Support\CommandRegistry;
use NixPHP\OAuth\Server\Commands\{ClientCreateCommand, ClientListCommand, ClientRotateSecretCommand,
    DoctorCommand, KeysGenerateCommand, KeysPruneCommand, SetupCommand};
use NixPHP\Database\Core\Database;
use NixPHP\Database\Support\MigrationRegistry;
use NixPHP\OAuth\Server\Core\{Authorization, Claims, ClientAuthenticator, Discovery, IdTokenIssuer,
    ResourceServer, ScopePolicy, TokenEndpoint, UserInfoEndpoint, Users};
use NixPHP\OAuth\Server\Exception\ConfigurationException;
use NixPHP\OAuth\Server\Store\{ClientStoreInterface, FileKeys, KeyStoreInterface,
    PdoClients, PdoTokens, TokenStoreInterface};
use Psr\Http\Message\ServerRequestInterface;
use function NixPHP\app;
use function NixPHP\Auth\auth;
use function NixPHP\config;

$container = app()->container();

/**
 * The adapters need a PDO connection, and nixphp/database registers a Database.
 * Bridging that here means an ordinary installation resolves on its own instead
 * of asking for a container binding nobody would think to write.
 */
if (!$container->has(PDO::class) && app()->hasPlugin('nixphp/database')) {
    $container->set(PDO::class, static function () use ($container): PDO {
        $connection = $container->get(Database::class)?->getConnection();

        if (!$connection instanceof PDO) {
            throw new ConfigurationException(
                'nixphp/database is installed but has no connection configured, so there is no '
                . PDO::class . ' to work with. Configure "database", or bind your own connection.'
            );
        }

        return $connection;
    });
}

// Factories run on first use. Application bindings take precedence, so an
// installation that keeps its clients or tokens somewhere else binds its own.
if (!$container->has(ClientStoreInterface::class)) {
    $container->set(ClientStoreInterface::class, static fn(): ClientStoreInterface => new PdoClients(
        $container->get(PDO::class),

        // The hasher nixphp/auth registers, so an application that raises its
        // hashing cost raises it for client secrets too.
        $container->get(PasswordHasher::class),
    ));
}

if (!$container->has(TokenStoreInterface::class)) {
    $container->set(TokenStoreInterface::class, static fn(): TokenStoreInterface => new PdoTokens(
        $container->get(PDO::class),
    ));
}

if (!$container->has(ScopePolicy::class)) {
    $container->set(ScopePolicy::class, static fn(): ScopePolicy => new ScopePolicy(
        (array) config('oauth_server:scopes', []),
    ));
}

if (!$container->has(ClientAuthenticator::class)) {
    $container->set(ClientAuthenticator::class, static fn(): ClientAuthenticator => new ClientAuthenticator(
        $container->get(ClientStoreInterface::class),
        $container->get(PasswordHasher::class),
    ));
}

if (!$container->has(Authorization::class)) {
    $container->set(Authorization::class, static fn(): Authorization => new Authorization(
        clients: $container->get(ClientStoreInterface::class),
        tokens: $container->get(TokenStoreInterface::class),
        policy: $container->get(ScopePolicy::class),

        // A scope is offered only to somebody who holds the permission behind it,
        // answered by nixphp/auth about whoever is signed in right now.
        holdsPermission: static fn(string $permission): bool => auth()->can($permission),
        consentTtl: (int) config('oauth_server:consent_ttl', 600),
        codeTtl: (int) config('oauth_server:code_ttl', 60),
        signs: $container->get(KeyStoreInterface::class)->has(),
    ));
}

// ------------------------------------------------------------- OpenID Connect

/** The issuer every signed statement names. There is no trustworthy alternative. */
$issuer = static function (): string {
    $url = config('public_url');

    if (!is_string($url) || trim($url) === '') {
        throw new ConfigurationException(
            'public_url is required to issue ID tokens: it is the issuer relying parties check, '
            . 'and a request cannot be trusted to say where this server lives.'
        );
    }

    return rtrim(trim($url), '/');
};

if (!$container->has(KeyStoreInterface::class)) {
    $container->set(KeyStoreInterface::class, static fn(): KeyStoreInterface => new FileKeys(
        config('oauth_server:key_path') ?? app()->getBasePath() . '/storage/oauth/keys',
    ));
}

if (!$container->has(Users::class)) {
    $container->set(Users::class, static fn(): Users => new Users(
        static fn(string $provider, string $id) => auth()->load($provider, $id),
    ));
}

if (!$container->has(Claims::class)) {
    $container->set(Claims::class, static function (): Claims {
        $mapper = config('oauth_server:claims');

        if ($mapper !== null && !is_callable($mapper)) {
            throw new ConfigurationException('oauth_server:claims has to be callable.');
        }

        return new Claims(
            $mapper === null ? null : Closure::fromCallable($mapper),
            static fn(string $provider, string $id) => auth()->load($provider, $id),
        );
    });
}

if (!$container->has(IdTokenIssuer::class)) {
    $container->set(IdTokenIssuer::class, static fn(): IdTokenIssuer => new IdTokenIssuer(
        keys: $container->get(KeyStoreInterface::class),
        issuer: $issuer(),
        ttl: (int) config('oauth_server:id_token_ttl', 3600),
    ));
}

if (!$container->has(Discovery::class)) {
    $container->set(Discovery::class, static fn(): Discovery => new Discovery(
        issuer: $issuer(),
        policy: $container->get(ScopePolicy::class),
        keys: $container->get(KeyStoreInterface::class),
    ));
}

if (!$container->has(UserInfoEndpoint::class)) {
    $container->set(UserInfoEndpoint::class, static fn(): UserInfoEndpoint => new UserInfoEndpoint(
        $container->get(TokenStoreInterface::class),
        $container->get(Claims::class),
        $container->get(Users::class),
    ));
}

if (!$container->has(TokenEndpoint::class)) {
    $container->set(TokenEndpoint::class, static function () use ($container): TokenEndpoint {
        // Without a signing key this is an OAuth2 server, which is a complete
        // thing to be. Handing the endpoint a null issuer is what makes it one,
        // rather than a broken OIDC provider that fails at the first id_token.
        $signs = $container->get(KeyStoreInterface::class)->has();

        return new TokenEndpoint(
            authenticator: $container->get(ClientAuthenticator::class),
            tokens: $container->get(TokenStoreInterface::class),
            accessTtl: (int) config('oauth_server:access_token_ttl', 3600),
            refreshTtl: (int) config('oauth_server:refresh_token_ttl', 2592000),
            idTokens: $signs ? $container->get(IdTokenIssuer::class) : null,
            claims: $signs ? $container->get(Claims::class) : null,
            users: $container->get(Users::class),
        );
    });
}

if (!$container->has(ResourceServer::class)) {
    $container->set(ResourceServer::class, static fn(): ResourceServer => new ResourceServer(
        tokens: $container->get(TokenStoreInterface::class),
        policy: $container->get(ScopePolicy::class),

        // The same reload path a session restore takes, and nothing of the session
        // itself: a bearer token never reaches auth()'s own state.
        load: static fn(string $provider, string $id) => auth()->load($provider, $id),
        request: $container->get(ServerRequestInterface::class),
        audience: (string) config('oauth_server:audience', ''),
    ));
}

if (app()->hasPlugin('nixphp/database')) {
    MigrationRegistry::addPath(__DIR__ . '/src/Migrations');
}

if (app()->hasPlugin('nixphp/cli')) {
    $commands = $container->get(CommandRegistry::class);
    $commands->add(ClientCreateCommand::class);
    $commands->add(ClientListCommand::class);
    $commands->add(ClientRotateSecretCommand::class);
    $commands->add(KeysGenerateCommand::class);
    $commands->add(KeysPruneCommand::class);
    $commands->add(SetupCommand::class);
    $commands->add(DoctorCommand::class);
}
