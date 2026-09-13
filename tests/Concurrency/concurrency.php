<?php

/**
 * Concurrency check for nixphp/oauth-server against a real database.
 *
 * Real processes, not a simulation: N children fork, each opens its own
 * connection, and all of them wait on a wall-clock barrier before touching the
 * same row. What we want to see is "exactly one", every time.
 *
 * Usage: php tests/Concurrency/concurrency.php sqlite|mysql|pgsql [workers]
 */

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';

use NixPHP\Auth\Support\PasswordHasher;
use NixPHP\OAuth\Server\Exception\OAuthError;
use NixPHP\OAuth\Server\Migrations\OAuthServerMigration;
use NixPHP\OAuth\Server\Model\{AuthorizationRequest, Client};
use NixPHP\OAuth\Server\Store\{PdoClients, PdoTokens};

const VERIFIER = 'a-verifier-long-enough-to-be-one-43-chars-x';
const REDIRECT = 'https://intranet.example.test/callback';

$target  = $argv[1] ?? 'sqlite';
$workers = (int) ($argv[2] ?? 8);
$results = sys_get_temp_dir() . '/nixphp-conc-' . bin2hex(random_bytes(4));
@mkdir($results, 0700, true);

function connect(string $target): PDO
{
    $pdo = match ($target) {
        // Native prepares, deliberately: a named placeholder used twice in one
        // statement works only while PDO emulates them, and emulation off is a
        // common hardening setting. Emulating here would hide that entirely.
        'mysql'  => new PDO('mysql:host=127.0.0.1;port=13306;dbname=oauth;charset=utf8mb4', 'root', 'secret', [
            PDO::ATTR_EMULATE_PREPARES => false,
        ]),
        'pgsql'  => new PDO('pgsql:host=127.0.0.1;port=15432;dbname=oauth', 'postgres', 'secret'),
        default  => new PDO('sqlite:' . sys_get_temp_dir() . '/nixphp-conc.sqlite'),
    };

    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    if ($target === 'sqlite') {
        $pdo->exec('PRAGMA busy_timeout = 5000');
    }

    return $pdo;
}

function request(Client $client, string $user = '42'): AuthorizationRequest
{
    return new AuthorizationRequest(
        clientId: $client->id,
        redirectUri: REDIRECT,
        scopes: ['posts.read'],
        state: 'state-1',
        codeChallenge: rtrim(strtr(base64_encode(hash('sha256', VERIFIER, true)), '+/', '-_'), '='),
        nonce: null,
        audience: '',
        sessionId: 'session-1',
        userProvider: 'database',
        userId: $user,
    );
}

/**
 * Fork $workers children, each running $work at the same moment on its own
 * connection, and collect what they say.
 */
function race(string $target, int $workers, string $results, string $label, Closure $work): array
{
    $startAt = microtime(true) + 0.4;
    $pids    = [];

    for ($i = 0; $i < $workers; $i++) {
        $pid = pcntl_fork();

        if ($pid === -1) {
            throw new RuntimeException('Could not fork.');
        }

        if ($pid === 0) {
            // Child: its own connection. A forked one is shared, and that is not
            // a thing two processes may do.
            $outcome = ['worker' => $i];

            try {
                $tokens = new PdoTokens(connect($target));

                while (microtime(true) < $startAt) {
                    usleep(200);
                }

                $outcome += ['ok' => true, 'value' => $work($tokens)];
            } catch (OAuthError $e) {
                $outcome += ['ok' => false, 'error' => $e->error];
            } catch (Throwable $e) {
                $outcome += ['ok' => false, 'error' => $e::class, 'message' => substr($e->getMessage(), 0, 120)];
            }

            file_put_contents($results . '/' . $label . '-' . $i . '.json', json_encode($outcome));
            exit(0);
        }

        $pids[] = $pid;
    }

    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }

    $collected = [];

    foreach (glob($results . '/' . $label . '-*.json') ?: [] as $file) {
        $collected[] = json_decode((string) file_get_contents($file), true);
    }

    return $collected;
}

function report(string $label, array $outcomes, int $expectedWinners, array &$failures): void
{
    $won    = array_values(array_filter($outcomes, static fn(array $o): bool => $o['ok'] === true));
    $errors = [];

    foreach ($outcomes as $outcome) {
        if ($outcome['ok'] === false) {
            $errors[$outcome['error']] = ($errors[$outcome['error']] ?? 0) + 1;
        }
    }

    $unexpected = array_diff_key($errors, ['invalid_grant' => 1, 'invalid_request' => 1]);
    $good       = count($won) === $expectedWinners && $unexpected === [];

    if (!$good) {
        $failures[] = $label;
    }

    printf(
        "  %-34s %s  %d/%d erfolgreich   %s\n",
        $label,
        $good ? 'OK  ' : 'FEHL',
        count($won),
        count($outcomes),
        $errors === [] ? '' : json_encode($errors),
    );
}

// ---------------------------------------------------------------- Setup

printf("\n%s  (%d parallele Prozesse)\n", strtoupper($target), $workers);

$pdo       = connect($target);
$migration = new OAuthServerMigration();
$migration->down($pdo);
$migration->up($pdo);

[$client] = (new PdoClients($pdo, new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4])))->register(
    name: 'Acme Intranet',
    redirectUris: [REDIRECT],
    grants: ['authorization_code', 'refresh_token'],
    scopes: ['posts.read'],
    confidential: true,
);

$tokens   = new PdoTokens($pdo);
$failures = [];

// A — one authorization code, many redeemers.
$code = $tokens->issueCode(request($client), 60);
$pdo  = null;
report('Code einlösen', race($target, $workers, $results, 'code',
    static fn(PdoTokens $t): string => $t->redeem($code, $client, REDIRECT, VERIFIER, 3600, 86400)->accessToken,
), 1, $failures);

// B — one refresh token, many rotators.
$pdo    = connect($target);
$tokens = new PdoTokens($pdo);
$issued = $tokens->redeem($tokens->issueCode(request($client, '43'), 60), $client, REDIRECT, VERIFIER, 3600, 86400);
$refresh = (string) $issued->refreshToken;
$pdo = null;
report('Refresh rotieren', race($target, $workers, $results, 'refresh',
    static fn(PdoTokens $t): string => $t->rotate($refresh, $client, 3600, 86400)->accessToken,
), 1, $failures);

// C — one consent, many answers.
$pdo       = connect($target);
$tokens    = new PdoTokens($pdo);
$requestId = $tokens->storeRequest(request($client, '44'), 600);
$pdo = null;
report('Consent einlösen', race($target, $workers, $results, 'consent',
    static fn(PdoTokens $t): string => $t->consumeRequest($requestId, 'session-1', 'database', '44')->clientId,
), 1, $failures);

// D — many processes asking for the same subject at once. Here everybody should
// win, and they should all get the same answer.
$subjects = race($target, $workers, $results, 'subject',
    static fn(PdoTokens $t): string => $t->subjectFor('database', '99'),
);
$values = array_unique(array_column(array_filter($subjects, static fn(array $s): bool => $s['ok']), 'value'));
$sameSubject = count($values) === 1 && count(array_filter($subjects, static fn(array $s): bool => $s['ok'])) === $workers;
if (!$sameSubject) { $failures[] = 'Subjekt vergeben'; }
printf("  %-34s %s  %d/%d erfolgreich   %s\n", 'Subjekt vergeben', $sameSubject ? 'OK  ' : 'FEHL',
    count(array_filter($subjects, static fn(array $s): bool => $s['ok'])), $workers,
    count($values) === 1 ? 'alle identisch' : 'ABWEICHEND: ' . json_encode(array_values($values)));

// ---- Did the replay of the code actually revoke what the winner got?
$pdo    = connect($target);
$tokens = new PdoTokens($pdo);
$winner = null;
foreach (glob($results . '/code-*.json') ?: [] as $file) {
    $o = json_decode((string) file_get_contents($file), true);
    if ($o['ok']) { $winner = $o['value']; }
}
$revoked = $winner !== null && $tokens->inspect($winner) === null;
if (!$revoked) { $failures[] = 'Familienwiderruf nach Replay'; }
printf("  %-34s %s  %s\n", 'Familienwiderruf nach Replay', $revoked ? 'OK  ' : 'FEHL',
    $revoked ? 'Token des Gewinners entwertet' : 'Token lebt noch');

array_map('unlink', glob($results . '/*') ?: []);
@rmdir($results);

printf("\n  %s\n", $failures === [] ? 'Alles wie erwartet.' : 'FEHLGESCHLAGEN: ' . implode(', ', $failures));
exit($failures === [] ? 0 : 1);
