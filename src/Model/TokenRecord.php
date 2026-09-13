<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Model;

/** A live access token, as the resource server sees it. */
final readonly class TokenRecord
{
    /** @param list<string> $scopes */
    public function __construct(
        public string $clientId,
        public ?string $userProvider,
        public ?string $userId,
        public array $scopes,
        public string $audience,
        public int $expiresAt,
    ) {}

    /** Client-credentials tokens stand for an application. There is no person behind them. */
    public function isApplication(): bool
    {
        return $this->userId === null;
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
