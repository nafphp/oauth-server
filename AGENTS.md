# Working on naf/oauth-server

NAF is a small PHP framework with optional Composer plugins. Its core owns boot,
configuration, the service container, routing, events and PSR-7 responses. Prefer existing
NAF helpers, services and extension interfaces; keep application business rules in the host.
This package declares `type: naf-plugin` and is discovered after installation in a NAF host.
The plugin repository itself is not the application's web root.

Before changing code, read the [shared contribution workflow](https://github.com/nafphp/docs/blob/main/AGENT_WORKFLOW.md)
and [release procedure](https://github.com/nafphp/docs/blob/main/RELEASING.md).
In the multi-repository workspace, the same documents are in the sibling `docs/` checkout;
use the linked copies when working from a standalone clone. Preserve other contributors' work.
Review and update user documentation with every behavior change. Source fixes use an RC branch;
verified documentation-only changes can be merged and published by the agent.

## What this plugin does

`naf/oauth-server` makes the host an OAuth2 authorization server and protects APIs with bearer
tokens. It integrates with `naf/auth`, sessions and forms. Install with
`composer require naf/oauth-server`; configure issuer, signing keys, PDO/storage and account
providers, run migrations and register clients as described in the guide. This is distinct
from signing in through an external provider (`naf/oauth-client`).

## Use it

Inside an API handler after the server plugin is configured:

```php
<?php
use function Naf\OAuth\Server\token;
use function Naf\json;

token()->requireScope('reports.read');
return json(['clientId' => token()->clientId()]);
```

`token()` describes bearer authorization, never the browser login. `requireScope()` performs
the effective authorization check; inspect `TokenContext` before substituting a lower-level
scope-presence test. Do not accept a browser session as a missing API token or skip user/account
restrictions merely because the token contains a scope string.

## Change it here

Read [bootstrap](bootstrap.php), [core services](src/Core/), [TokenContext](src/Core/TokenContext.php),
[configuration](src/config.php), [routes](src/routes.php), [commands](src/Commands/) and the
storage contracts under [src](src/). Reuse the existing protocol and storage implementation.
Preserve single-use authorization codes, refresh-family replay handling, PKCE, client and
redirect validation, scope narrowing and key/token secrecy. Register protocol CSRF exemptions
by exact route name while preserving their independent client/token authentication.

## Verify

Run `composer test`, `composer analyse` and `composer validate --strict`; use
`Tests\CommandTestCase` for CLI changes and [tests](tests/) for protocol fixtures.
Before a release, run both real-process concurrency scripts against **SQLite, PostgreSQL and
MySQL**, exactly as described in [tests/Concurrency/README.md](tests/Concurrency/README.md).
The PHPUnit suite does not run them and SQLite alone cannot prove the locking guarantees.
Use throwaway databases and clean up only those test resources.

User docs: [OAuth server](https://nafphp.github.io/docs/oauth-server/).
