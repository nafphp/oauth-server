<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Model\IssuedTokens;
use SensitiveParameter;

/** Optional store capability: validate the requested resource inside code redemption. */
interface ResourceTokenStoreInterface extends TokenStoreInterface
{
    public function redeemForResource(
        #[SensitiveParameter]
        string $code,
        Client $client,
        ?string $redirectUri,
        #[SensitiveParameter]
        string $verifier,
        int $accessTtl,
        int $refreshTtl,
        string $resource,
    ): IssuedTokens;
}
