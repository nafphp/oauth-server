<?php

declare(strict_types=1);

namespace NixPHP\OAuth\Server\Exception;

use RuntimeException;
use Throwable;

/**
 * A protocol error, in the shape RFC 6749 §5.2 asks for.
 *
 * Two things decide how one of these leaves the server, and both are carried
 * here rather than worked out at the edge:
 *
 * - `$status`, because `invalid_client` answers 401 while everything else
 *   answers 400, and getting that wrong breaks well-behaved clients;
 * - `$redirectable`, because an error may only be sent back to a redirect URI
 *   once that URI has been established as genuinely belonging to the client.
 *   Before then — an unknown client, a URI that does not match — the only safe
 *   place to say so is our own page.
 */
final class OAuthError extends RuntimeException
{
    private function __construct(
        public readonly string $error,
        public readonly string $description,
        public readonly int $status,
        public readonly bool $redirectable,
        public readonly ?string $redirectUri = null,
        public readonly string $state = '',
        ?Throwable $previous = null,
    ) {
        parent::__construct($error . ': ' . $description, 0, $previous);
    }

    /** The request never established a trustworthy redirect URI, so nothing is redirected. */
    public static function refuse(string $error, string $description, int $status = 400, ?Throwable $previous = null): self
    {
        return new self($error, $description, $status, redirectable: false, previous: $previous);
    }

    /** The client and its redirect URI are known good; the client itself is told. */
    public static function redirect(string $error, string $description): self
    {
        return new self($error, $description, 400, redirectable: true);
    }

    /**
     * Attach the destination, once the request has established one.
     *
     * Thrown deep inside validation, an error knows what went wrong but not yet
     * where to say so. This fills that in at the one point where the redirect URI
     * has been matched against the registration — and leaves an error that must
     * not be redirected exactly as it was.
     */
    public function to(string $redirectUri, string $state): self
    {
        if (!$this->redirectable) {
            return $this;
        }

        return new self($this->error, $this->description, $this->status, true, $redirectUri, $state, $this);
    }

    /** Where to send the browser, or null when this error must not leave our own page. */
    public function redirectTarget(): ?string
    {
        if (!$this->redirectable || $this->redirectUri === null) {
            return null;
        }

        $parameters = ['error' => $this->error, 'error_description' => $this->description];

        if ($this->state !== '') {
            $parameters['state'] = $this->state;
        }

        return $this->redirectUri
            . (str_contains($this->redirectUri, '?') ? '&' : '?')
            . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /** @return array<string, string> The JSON body of a token or introspection error. */
    public function body(): array
    {
        return ['error' => $this->error, 'error_description' => $this->description];
    }
}
