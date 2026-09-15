<div align="center">

![NAF](assets/naf-logo-small-square.png)

[![NAF OAuth Server Plugin](https://github.com/nafphp/oauth-server/actions/workflows/php.yml/badge.svg)](https://github.com/nafphp/oauth-server/actions/workflows/php.yml)

</div>

[← Back to NAF](https://github.com/nafphp/framework)

---

# naf/oauth-server

> **Be the place people sign in with — an OAuth2 authorization server and OpenID Connect provider, on the accounts you already have.**

```php
token()->requireScope('posts.write');
```

That is the whole of what an API endpoint has to say. The authorization, the consent, the
tokens and their revocation are already wired.

> 🧩 Part of the official NAF plugin collection.
> Install it when other applications should be able to act on behalf of your users.

## Documentation

**[Being the provider →](https://nafphp.github.io/docs/oauth-server/)**

Everything about this package — what it does, how it is configured and what it needs — lives
in the [NAF documentation](https://nafphp.github.io/docs/). Not sure which packages you need?
[Start here](https://nafphp.github.io/docs/choosing-packages/).

## Install

```bash
composer require naf/oauth-server
```

## License

MIT. Part of [NAF](https://github.com/nafphp/framework).

## PHP code style

Source, tests and PHP templates follow the shared [NAF code style](https://github.com/nafphp/docs/blob/main/CODE_STYLE.md)
(PER Coding Style 3.0 with the Nafinity readability rules). After `composer install`, run
`composer style:check` to verify formatting or `composer style:fix` to apply it. The formatter
is a development dependency. Review template output and run the package checks after changes.
