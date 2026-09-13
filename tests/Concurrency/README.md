# Concurrency checks

These are not unit tests and PHPUnit does not run them. They fork real processes,
each with its own connection, and have them reach for the same row at the same
moment on a wall-clock barrier. What they check cannot be checked any other way:
the guarantees here are properties of the database, not of the code.

**SQLite is not enough.** It serialises write transactions, so it answers
correctly whatever the code does — and hid a real defect in exactly these
operations until they were run against the other two. Run all three.

```bash
docker compose -f tests/Concurrency/docker-compose.yml up -d

php tests/Concurrency/concurrency.php sqlite 16
php tests/Concurrency/concurrency.php pgsql  16
php tests/Concurrency/concurrency.php mysql  16

php tests/Concurrency/replay_race.php sqlite 40
php tests/Concurrency/replay_race.php pgsql  40
php tests/Concurrency/replay_race.php mysql  40

docker compose -f tests/Concurrency/docker-compose.yml down -v
```

Both scripts exit non-zero when something is wrong.

## concurrency.php — exactly one

N processes reach for one authorization code, one refresh token, one pending
consent. Exactly one may win each; the rest must be refused, and the refusal must
be `invalid_grant` or `invalid_request` rather than a deadlock or a driver error.
The fourth case is the opposite: N processes asking for the same subject must all
succeed and must all get the same value.

## replay_race.php — the interleaving

A spent refresh token is replayed at the very moment the legitimate client
rotates the current one. Replay detection has to end the whole family, including
the successor being issued a millisecond away.

This is the one SQLite cannot show. Before `oauth_families` existed, PostgreSQL
leaked a surviving token in 40 of 40 rounds and MySQL in 21 of 40, while SQLite
reported clean — the revocation and the issuing were passing each other, each in
its own transaction. Issuing now claims the family row and revoking takes it, so
one waits for the other.
