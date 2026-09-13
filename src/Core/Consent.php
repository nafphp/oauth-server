<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Core;

/** What a consent screen needs, and nothing that could be posted back and believed. */
final readonly class Consent
{
    /** @param list<array{scope: string, label: string}> $scopes */
    public function __construct(
        public string $requestId,
        public string $clientName,
        public array $scopes,
    ) {}
}
