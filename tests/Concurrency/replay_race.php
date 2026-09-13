<?php

/**
 * The nastiest interleaving I can think of.
 *
 * Replay detection revokes the family in a transaction of its own, after the
 * failed claim has rolled back. So: what happens when somebody replays a spent
 * refresh token at the very moment the legitimate client rotates the current one?
 *
 * If the revocation and the issuing pass each other, a stolen chain survives the
 * detection that was supposed to end it. This runs both at once, many times, and
 * counts how often anything from the family is still alive afterwards.
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use Naf\Auth\Support\PasswordHasher;
use Naf\OAuth\Server\Migrations\OAuthServerMigration;
use Naf\OAuth\Server\Model\{AuthorizationRequest, Client};
use Naf\OAuth\Server\Store\{PdoClients, PdoTokens};

const VERIFIER = 'a-verifier-long-enough-to-be-one-43-chars-x';
const REDIRECT = 'https://intranet.example.test/callback';

$target = $argv[1] ?? 'sqlite';
$rounds = (int) ($argv[2] ?? 40);
$dir    = sys_get_temp_dir() . '/naf-race-' . bin2hex(random_bytes(4));
@mkdir($dir, 0700, true);

function connect(string $target): PDO
{
    $pdo = match ($target) {
        'mysql' => new PDO('mysql:host=127.0.0.1;port=13306;dbname=oauth;charset=utf8mb4', 'root', 'secret', [
            PDO::ATTR_EMULATE_PREPARES => false,
        ]),
        'pgsql' => new PDO('pgsql:host=127.0.0.1;port=15432;dbname=oauth', 'postgres', 'secret'),
        default => new PDO('sqlite:' . sys_get_temp_dir() . '/naf-race.sqlite'),
    };
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    if ($target === 'sqlite') { $pdo->exec('PRAGMA busy_timeout = 5000'); }
    return $pdo;
}

function request(Client $client, string $user): AuthorizationRequest
{
    return new AuthorizationRequest(
        clientId: $client->id, redirectUri: REDIRECT, scopes: ['posts.read'], state: 's',
        codeChallenge: rtrim(strtr(base64_encode(hash('sha256', VERIFIER, true)), '+/', '-_'), '='),
        nonce: null, audience: '', sessionId: 'session-1', userProvider: 'database', userId: $user,
    );
}

$pdo = connect($target);
(new OAuthServerMigration())->down($pdo);
(new OAuthServerMigration())->up($pdo);

[$client] = (new PdoClients($pdo, new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4])))->register(
    'Acme', [REDIRECT], ['authorization_code', 'refresh_token'], ['posts.read'], confidential: true,
);

$leaks = 0;
$detected = 0;

for ($round = 0; $round < $rounds; $round++) {
    $tokens = new PdoTokens(connect($target));

    // A family two rotations deep: R1 spent, R2 current.
    $first  = $tokens->redeem($tokens->issueCode(request($client, (string) $round), 60), $client, REDIRECT, VERIFIER, 3600, 86400);
    $second = $tokens->rotate((string) $first->refreshToken, $client, 3600, 86400);

    $spent   = (string) $first->refreshToken;   // the attacker's copy
    $current = (string) $second->refreshToken;  // what the real client holds

    $startAt = microtime(true) + 0.25;
    $pids    = [];

    foreach (['replay' => $spent, 'rotate' => $current] as $role => $token) {
        $pid = pcntl_fork();

        if ($pid === 0) {
            $t = new PdoTokens(connect($target));
            while (microtime(true) < $startAt) { usleep(100); }

            $outcome = ['role' => $role];
            try {
                $issued = $t->rotate($token, $client, 3600, 86400);
                $outcome += ['ok' => true, 'access' => $issued->accessToken, 'refresh' => $issued->refreshToken];
            } catch (Throwable $e) {
                $outcome += ['ok' => false, 'error' => $e->error ?? $e::class];
            }

            file_put_contents($dir . '/' . $role . '.json', json_encode($outcome));
            exit(0);
        }

        $pids[] = $pid;
    }

    foreach ($pids as $pid) { pcntl_waitpid($pid, $status); }

    $replay = json_decode((string) @file_get_contents($dir . '/replay.json'), true);
    $rotate = json_decode((string) @file_get_contents($dir . '/rotate.json'), true);
    @unlink($dir . '/replay.json');
    @unlink($dir . '/rotate.json');

    if (($replay['ok'] ?? true) === true) {
        // A spent token was accepted. That would be a different and worse bug.
        printf("  Runde %-3d SPENT TOKEN AKZEPTIERT\n", $round);
        $leaks++;
        continue;
    }

    $detected++;

    // Detection happened. Now: did anything from this family survive it?
    $check = new PdoTokens(connect($target));
    $alive = [];

    if (($rotate['ok'] ?? false) === true) {
        if ($check->inspect($rotate['access']) !== null) { $alive[] = 'access'; }

        try {
            $check->rotate((string) $rotate['refresh'], $client, 3600, 86400);
            $alive[] = 'refresh';
        } catch (Throwable) {
            // good: the successor is dead too
        }
    }

    if ($alive !== []) {
        $leaks++;
        if ($leaks <= 3) {
            printf("  Runde %-3d ueberlebt: %s\n", $round, implode(', ', $alive));
        }
    }
}

array_map('unlink', glob($dir . '/*') ?: []);
@rmdir($dir);

printf("\n%-7s  %d Runden, %d Replays erkannt, %d mit ueberlebendem Token  -> %s\n",
    strtoupper($target), $rounds, $detected, $leaks,
    $leaks === 0 ? 'sauber' : 'RENNEN NACHGEWIESEN');

exit($leaks === 0 ? 0 : 1);
