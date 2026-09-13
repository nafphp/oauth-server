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
