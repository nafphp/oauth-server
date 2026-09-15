<?php

declare(strict_types=1);

namespace Naf\OAuth\Server\Store;

use Naf\OAuth\Server\Model\SigningKey;
use RuntimeException;

/**
 * Signing keys as files on disk.
 *
 * Deliberately not in the database and deliberately not generated on demand: a
 * key that appears when a request needs one is a key that changes when a second
 * server starts, and every token signed by the one that went away stops
 * verifying. These are created once, by hand, and kept.
 *
 * One key signs and all of them are published. Rotating generates a new one and
 * marks whatever signed before as retired, with the moment it stopped — because
 * that, not the day it was created, is when its retention starts counting. A key
 * that signed for a year and was replaced a minute ago still has tokens in the
 * world for as long as those tokens live.
 */
final class FileKeys implements KeyStoreInterface
{
    private const string PREFIX  = 'oidc-';
    private const string SUFFIX  = '.pem';
    private const string RETIRED = '.retired';

    public function __construct(private readonly string $path)
    {
    }

    public function has(): bool
    {
        return $this->files() !== [];
    }

    public function active(): SigningKey
    {
        $files = array_values(array_filter($this->files(), fn(string $f): bool => $this->retiredAt($f) === null));

        if ($files === []) {
            throw new RuntimeException(
                'No signing key exists yet. Run "naf oauth:keys:generate" once before issuing ID tokens.',
            );
        }

        return $this->read($files[0]);
    }

    public function all(): array
    {
        return array_map($this->read(...), $this->files());
    }

    public function generate(): SigningKey
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);

        if ($key === false || !openssl_pkey_export($key, $pem)) {
            throw new RuntimeException('Could not generate a signing key.');
        }

        if (!is_dir($this->path) && !@mkdir($this->path, 0700, true) && !is_dir($this->path)) {
            throw new RuntimeException('Could not create the key directory: ' . $this->path);
        }

        // The id carries the moment it was made, which is also the order they sign
        // in; the random half keeps two keys made in the same second apart.
        $id   = self::PREFIX . time() . '-' . bin2hex(random_bytes(4));
        $file = $this->path . '/' . $id . self::SUFFIX;

        // Written aside and moved into place: a half-written key file is a key
        // that signs tokens nobody can check.
        $temporary = $file . '.' . bin2hex(random_bytes(6));

        if (@file_put_contents($temporary, $pem) === false) {
            throw new RuntimeException('Could not write the signing key to ' . $this->path);
        }

        @chmod($temporary, 0600);

        if (!@rename($temporary, $file)) {
            @unlink($temporary);

            throw new RuntimeException('Could not move the signing key into place at ' . $file);
        }

        // Whatever signed until now stops signing now, and that moment — not the
        // day it was created — is when its retention starts counting.
        foreach ($this->files() as $existing) {
            if ($existing !== $file && $this->retiredAt($existing) === null) {
                @file_put_contents($existing . self::RETIRED, (string) time());
            }
        }

        return new SigningKey($id, (string) $pem);
    }

    public function prune(int $maximumAge): array
    {
        $cutoff  = time() - $maximumAge;
        $removed = [];

        foreach ($this->files() as $file) {
            $retired = $this->retiredAt($file);

            // A key still in use is kept however old it is, and a retired one is
            // kept until everything it signed has expired. When it was created
            // says nothing about either: a key that signed for a year and was
            // replaced a minute ago has tokens in the world for an hour yet.
            if ($retired === null || $retired >= $cutoff) {
                continue;
            }

            if (@unlink($file)) {
                @unlink($file . self::RETIRED);
                $removed[] = self::idOf($file);
            }
        }

        return $removed;
    }

    /** When this key stopped signing, or null while it still does. */
    private function retiredAt(string $file): ?int
    {
        $marker = @file_get_contents($file . self::RETIRED);

        return is_string($marker) && ctype_digit(trim($marker)) ? (int) trim($marker) : null;
    }

    // ---------------------------------------------------------------- Internals

    /** @return list<string> Newest first, so the first entry is the one that signs. */
    private function files(): array
    {
        $files = glob($this->path . '/' . self::PREFIX . '*' . self::SUFFIX) ?: [];

        usort($files, static fn(string $a, string $b): int
            => self::createdAt(self::idOf($b)) <=> self::createdAt(self::idOf($a)) ?: strcmp($b, $a));

        return $files;
    }

    private function read(string $file): SigningKey
    {
        $pem = @file_get_contents($file);

        if ($pem === false) {
            throw new RuntimeException('Could not read the signing key ' . $file);
        }

        return new SigningKey(self::idOf($file), $pem);
    }

    private static function idOf(string $file): string
    {
        return basename($file, self::SUFFIX);
    }

    private static function createdAt(string $id): int
    {
        return (int) (explode('-', substr($id, strlen(self::PREFIX)))[0] ?? 0);
    }
}
