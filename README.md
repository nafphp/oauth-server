<div align="center">

![NixPHP](https://nixphp.github.io/docs/assets/nixphp-logo-small-square.png)

[![NixPHP OAuth Server Plugin](https://github.com/nixphp/oauth-server/actions/workflows/php.yml/badge.svg)](https://github.com/nixphp/oauth-server/actions/workflows/php.yml)

</div>

[← Back to NixPHP](https://github.com/nixphp/framework)

---

# nixphp/oauth-server

> **Be the place people sign in with — an OAuth2 authorization server and OpenID Connect provider, on the accounts you already have.**

```php
token()->requireScope('posts.write');
```

That is the whole of what an API endpoint has to say. The authorization, the consent, the
tokens and their revocation are already wired.

> 🧩 Part of the official NixPHP plugin collection.
> Install it when other applications should be able to act on behalf of your users.

---

## What this plugin is

An OAuth2 authorization server, and an OpenID Connect provider on top of it, built on the
accounts you already have. It does not introduce a second user model, a second login, or a
second idea of what somebody is allowed to do — it uses `nixphp/auth` for all three.

| Grant | |
| --- | --- |
| **Authorization Code** | with PKCE/S256, mandatory for every client, confidential ones included |
| **Refresh Token** | with strict rotation and replay detection |
| **Client Credentials** | for an application acting as itself |

OpenID Connect comes with it: ID tokens, UserInfo, discovery and a published key set. A client
opts into it per request by asking for the `openid` scope — it is not a mode the server is in.

Deliberately not offered: the Implicit and Password grants, wildcard redirect URIs, and the
`max_age` and `prompt` parameters.

---

## 📥 Installation

```bash
composer require nixphp/oauth-server nixphp/database nixphp/cli
vendor/bin/nix db:migrate up
vendor/bin/nix oauth:server:setup     # creates the signing key, says what is left
vendor/bin/nix oauth:server:doctor    # checks the rest before anybody tries
```

`nixphp/auth`, `nixphp/session` and `nixphp/form` come with it — the accounts, the sign-in that
consent is bound to, and the CSRF token on the consent form.

The key is what signs ID tokens, and it has to exist **before** anybody asks for OpenID
Connect: without one, a request for the `openid` scope is refused at the authorization endpoint
rather than accepted and then answered without an ID token. Skip the key and this is an OAuth2
server — a complete thing to be, and the discovery document says exactly that instead of
advertising what it cannot answer.

A PDO connection is found on its own when `nixphp/database` is configured. Nothing to bind.

---

## Configuration

```php
// app/config.php
return [
    'public_url'   => 'https://id.example.com',
    'oauth_server' => [
        'name'   => 'Acme ID',
        'scopes' => [
            'posts.read'  => ['label' => 'Read your posts',  'permission' => 'posts.view'],
            'posts.write' => ['label' => 'Write your posts', 'permission' => 'posts.edit'],
        ],
    ],
];
```

That is everything that has no sensible default.

**`audience` stays empty for the ordinary case** — one server, one API, tokens that carry no
target. Set it only when this installation serves an API that clients name explicitly with the
`resource` parameter:

```php
'oauth_server' => ['audience' => 'https://reports.example.com', …],
```

From then on a token granted for anything else is not a weaker token here, it is not a token
here at all. Which API a grant is for is decided once, when the person authorizes, and carried
through every refresh — changing a client's registration later cannot retarget tokens already
granted.

**`name` has none on purpose.** A sign-in service that ships somebody else's name is worse than
one that refuses to start. It is display only: it never reaches an issuer, a client id, a
redirect URI or a subject. OIDC discovery defines no field to publish it in either, so what a
relying party shows is whatever *its* configuration says — not this.

**Scopes are yours to define.** A scope is what a client asks for; a permission is what a person
holds. Keeping them separate means an API surface never leaks into the wording of a consent
screen. Leave `permission` out and the scope name is the permission; give a plain string instead
of an array and it is the label.

**`openid`, `profile` and `email` need no configuring.** OpenID Connect defines them, and none
of them requires a permission: they ask to see who somebody is and what their own profile says,
not to do anything on their behalf. The person consenting is the person concerned.

The sign-in page is found on its own when a route is named `login`; otherwise name it in
`oauth_server:login_route`. Lifetimes, PKCE and the protocol errors are already set.

### Saying more than "who"

**Usually nothing to configure.** A model implementing `UserInterface` already says what may be
shown about it through `getProfile()`, and that is what gets released — the same profile a
consent screen shows. One answer to "what may be said about this person", not one per consumer.

Configure `oauth_server:claims` only for something the profile does not cover:

```php
'oauth_server' => ['claims' => static fn(User $user): array => ['locale' => $user->locale]],
```

It adds to the profile rather than replacing it. Either way, what comes out is filtered by the
scopes that were actually granted: `email` releases `email` and `email_verified`, `profile`
releases the profile claims, and anything OpenID Connect defines no scope for is dropped rather
than passed along — including whatever a mapper returns by accident. With neither, an ID token
still says who somebody is; `sub` is the whole of what the specification requires.

---

## Registering an application

```bash
vendor/bin/nix oauth:client:create "Acme Intranet" \
    --redirect=https://intranet.example.com/auth/callback \
    --scope=posts.read,posts.write
```

```
  Acme Intranet
  Client ID       9f2c…
  Client secret   7b41…

  Copy the secret now. It is stored only as a hash and cannot be shown again.
```

Add `--public` for an application that cannot keep a secret — a mobile or desktop client. It is
then identified rather than authenticated, and PKCE is what protects its exchange.

`vendor/bin/nix oauth:client:list` shows what is registered.

**A public client cannot be given `--grant=introspection`.** A client id is not a secret — it
travels in every authorize URL — so a public client with that right would let anyone who has
ever seen a login link ask about anybody's tokens. The registry refuses the combination, and
the endpoint refuses it again.

### Rotating a client secret

```bash
vendor/bin/nix oauth:client:rotate-secret 9f2c…              # old one keeps working for a day
vendor/bin/nix oauth:client:rotate-secret 9f2c… --overlap=3600
vendor/bin/nix oauth:client:rotate-secret 9f2c… --now        # after a leak
```

The client id does not change, and nothing already issued is affected. That is the difference
between rotating a secret and replacing a client: replacing one means a new id in every
configuration that names it, and every existing authorization gone.

**The secret it replaces keeps working for the overlap.** It has to: the new secret exists on this
server before it exists in whatever deployment uses it, and a server that holds only one secret at
a time is a server on which nobody ever changes a secret, because doing so means breaking the
client until it is redeployed. Two are accepted, never three — rotating again inside a window
drops the older one.

`--now` ends the previous secret immediately, downtime included. That is what a leaked secret
calls for, and it is the only case where breaking the client is the right outcome.

The window is a deadline, not a state to clean up: it lapses on its own and nothing has to run.
Both `oauth:client:list` and `oauth:server:doctor` mark a rotation that is still open, so the
second half does not get forgotten — a client whose new secret was never deployed otherwise stops
working on a day nobody chose.

---

## Protecting an API

```php
use function NixPHP\OAuth\Server\token;

public function store(): ResponseInterface
{
    token()->requireScope('posts.write');

    $user = token()->user();   // your own model, or null for an application

    …
}
```

`requireScope()` raises 401 when no usable token was presented and 403 when the one that was
does not reach. `can()` is the same check as a plain bool.

### Two things have to hold, every time

- the **token** carries the scope — what the person agreed this application may do for them;
- the **person** still holds the permission behind it — what they may do at all.

So a read-only token stays read-only in an administrator's hands, and somebody demoted this
morning loses access this afternoon rather than whenever their token happens to expire.

A **client-credentials token stands for an application**, with nobody behind it. `user()` is
null and its registration is the whole answer; no person is invented to carry permissions.

### Bearer and session are separate worlds

There is no path from `token()` to a session. An expired, revoked or invented bearer token
cannot quietly fall back to whoever happens to be signed in with a cookie — a request with no
usable token has no usable token, whatever else it carries.

---

## Endpoints

| | |
| --- | --- |
| `GET /oauth/authorize` | ask the person |
| `POST /oauth/authorize` | their answer — CSRF-protected like any other form |
| `POST /oauth/token` | the three grants |
| `POST /oauth/revoke` | RFC 7009 |
| `POST /oauth/introspect` | RFC 7662, for a resource server elsewhere |
| `GET`/`POST` `/oauth/userinfo` | claims about whoever a token was issued for |
| `GET /.well-known/openid-configuration` | what this server does |
| `GET /.well-known/jwks.json` | the keys to check its signatures with |

Off with `'oauth_server' => ['routes' => false]`. The endpoints stay reachable through the
container.

Introspection is not open to every registered application: a token is somebody's authorization,
and being registered here is no reason to learn about other people's. Grant it deliberately with
`--grant=introspection`, to a confidential client.

### What a request has to say, and what it will not get away with

**`redirect_uri` is required** — in the authorization request and again at the token endpoint,
even for a client with exactly one registered URI. PKCE binds the exchange to the browser that
started it; this binds it to where the code was sent. They answer different questions, and
RFC 6749 §4.1.3 asks both.

**`prompt` and `max_age` are answered, not ignored.** This server always asks before granting
access and does not record when somebody last authenticated, so:

| | |
| --- | --- |
| `prompt=none` | `interaction_required` |
| `prompt=login` | `invalid_request` — re-authentication cannot be forced |
| `max_age=…` | `invalid_request` — the last authentication time is not recorded |
| `prompt=consent` | satisfied, because consent is always asked for |

Silently ignoring these is the worst answer available: a relying party that asked for
re-authentication and got an ordinary session back has been told something untrue about the
person in front of it.

---

## The consent screen

Shipped, and overridden by putting your own `oauth/consent.phtml` in the application's view
directory. Nothing in the central configuration has to change for that.

Its CSRF token belongs to the one request it was rendered for, derived from that request and
keyed by the session. A single session-wide token cannot do that job: issuing the second one
invalidates the first, so two consent screens open at once would break each other. This route is
therefore exempt from the session-wide check and carries its own — it is not unprotected.

The browser is handed an opaque request id and nothing else — no client, no scope, no redirect
URI. Consent is given for the request **the server validated**, and what comes back is only ever
a key to look it up by. It is bound to the browser it was asked in and to the person who was
asked: if somebody else signs in between the question and the answer, the request is void.

---

## Signing keys

One key signs; every key stays published until you say otherwise. That is what makes rotating
safe:

```bash
vendor/bin/nix oauth:keys:generate    # the new key signs from now on
vendor/bin/nix oauth:keys:prune       # remove the old ones, once their tokens have expired
```

`prune` counts from when a key **stopped signing**, not from when it was made. That distinction
is the whole point: a key that signed for a year and was replaced a minute ago has tokens in the
world for as long as those tokens live, and removing it would make every one of them
unverifiable. The active key is never removed, and an age shorter than an ID token lives is
refused.

Keys are files, not rows, and are never generated on demand. A key that appears when a request
needs one is a key that differs on the second server, and every token signed by the one that
went away stops verifying.

---

## The same user contract

This server signs people in with `nixphp/auth`, using the very model your application already
uses — `UserInterface`, `isActive()`, `getProfile()`. There is no second user table, no second
login and no second idea of what somebody may do. A suspended account stops working here at the
same moment it stops working everywhere else.

---

## Some decisions, and why

**Access tokens are opaque, not JWTs.** Revocation works without a second mechanism; a database
leak yields hashes rather than usable tokens; a changed scope or a demoted user takes effect on
the next call rather than the next token. A resource server running elsewhere uses authenticated
introspection. (ID tokens will be JWTs when OIDC ships — the specification says so.)

**Rotation is strict — there is no grace window.** Implementing one honestly would mean either
keeping a bearer token in plaintext so it can be handed out twice, or standing down replay
detection for its duration. Both undo the one thing rotation exists to do. A client that might
refresh twice at once should serialise its own refreshes.

**Withdrawing something withdraws what came from it.** Revoking a client takes its issued
tokens with it — otherwise revocation means nothing until they expire. An account that can no
longer sign in stops everywhere at once: no token is issued for it, no ID token minted, no
UserInfo answered. That question is asked in one place, so it cannot be answered in some paths
and skipped in the ones that assert identity.

**A family is a row, not just a column.** Everything descended from one authorization shares a
family id, and `oauth_families` is where its life ends. Issuing claims that row; revoking takes
it. Without that they pass each other: a replayed refresh token is detected, the revocation
sweeps the rows it can see, and a successor committed a millisecond later survives the very
detection that was supposed to end the chain. That is not theoretical — it is what the
concurrency checks found.

**A failed exchange keeps or gives back the code deliberately.** A code offered with the wrong
client, redirect URI or PKCE verifier is **spent**: it has evidently been somewhere it should
not have been, and going on accepting it is the worse outcome. A failure on *our* side rolls
back — nothing was issued, so nothing was spent.

**ID tokens are signed; access tokens are not.** The one exists because OpenID Connect defines
it as a JWT — a statement addressed to one application, which that application checks. The other
is a credential this server looks up, so a signature would buy nothing and cost revocation.

**Nothing bearable is stored in the clear.** Codes and tokens are SHA-256 hashes; client secrets
go through the same `PasswordHasher` `nixphp/auth` uses for people, so raising the hashing cost
raises it here too.

**A person is two columns, never one.** `user_provider` and `user_id` are the same pair
`nixphp/auth` persists in a session, because account ids are only unique within their source.
What the outside world sees is a subject: random, assigned once, never reused, and revealing
neither.

---

## Development

```bash
composer install
composer test
composer analyse
```

**A command is tested by running it.** `Tests\CommandTestCase` builds an application, boots the
plugin into it and executes the command against it, supplying only what a test cannot have: a
database in memory and a key directory that is not the repository. Nothing else is substituted —
`oauth:client:create` really registers a client, and the test then authenticates with the secret
it printed, because a printed secret that does not work is the one failure no class below the
command can have. The same goes for what a command tells somebody to run next: those hints are
checked against the commands this plugin actually registers.

Adding one looks like this:

```php
final class SomeCommandTest extends CommandTestCase
{
    public function testItSaysWhatItDid(): void
    {
        $this->healthy();                        // schema, config, one registered client

        $result = $this->execute(new SomeCommand(), ['--now']);

        $this->assertSucceeded($result);         // or assertFailed()
        self::assertSame('confidential', $result->value('Kind'));
    }
}
```

`healthy()` is an installation that passes every check, so a test can break one thing and read
what happens; `database()`, `configure()` and `boot()` sit underneath it for the cases that have
to start from less, and `register()` adds a client. `CommandResult` carries the exit status and
the printed output with the colour stripped — `line($label)` finds a row, `value($label)` returns
what follows the label, `lines()` gives the lot.

Two things it takes care of that are easy to get wrong in a harness of your own: keys go to a
temporary directory rather than into the repository — `oauth:keys:generate` writes real files —
and every service the plugin registers is reset between tests, so a case cannot pass on what the
one before it left behind.

The `repositories` block points at the sibling plugins in this workspace while they are
unreleased; it goes away, along with the `dev-main` constraints, once they are published.

Concurrency is checked with real forked processes against SQLite, MySQL 8.4 and PostgreSQL 17 —
see [tests/Concurrency](tests/Concurrency). PHPUnit does not run those; they need databases, and
they are the reason the guarantees above can be stated at all. The MySQL runs use **native
prepares** deliberately: a named placeholder reused within one statement works only while PDO
emulates them, and emulation off is a common hardening setting.

**Run all three before a release.** SQLite serialises write transactions, so it answers correctly
whatever the code does. It reported clean on an interleaving that PostgreSQL failed in 40 of 40
rounds.

CI covers PHP 8.3, 8.4 and 8.5.

### Upgrading

The schema has changed and is not backward compatible: authorizations now carry their target
API, families are rows of their own, and clients carry the secret they last replaced. Nothing is released yet, so the migration is meant to
be re-run rather than patched:

```bash
vendor/bin/nix db:migrate up      # after dropping the oauth_* tables of an earlier run
```

On MySQL the identifier columns are given a binary collation, because the default one is
case-insensitive and these hold values where `aB` and `Ab` are different identifiers.

---

## License

MIT License.
