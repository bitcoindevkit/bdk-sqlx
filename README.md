# bdk-sqlx

## Status

This crate is still **EXPERIMENTAL** do not use with mainnet wallets.

## Resolved defects

The following defects were found in review and are fixed; each is guarded by
an always-on regression test in the suite (`src/test.rs` and
`tests/builder_network.rs`):

- `tx.last_seen` for a tx not yet stored was silently dropped (the `UPDATE`
  affected 0 rows); the write now upserts a stub row (`whole_tx` is nullable).
- Reads anchored on the `network` row, so rows persisted by a changeset that
  carried no network were written but never read back; tx/block tables are now
  read unconditionally.
- A changeset mapping the same block hash to several heights silently
  collapsed to one block row, losing checkpoints; such changesets are now
  rejected with `DuplicateBlockHash`.
- The postgres `write` path did not validate `changeset.network` against the
  configured network, letting a foreign network overwrite the row and wedge
  all subsequent reads; the write is now rejected with `InvalidNetwork`.
- `keychain.last_revealed INTEGER DEFAULT 0` made a wallet persisted before
  its first address reveal reload with index 0 marked as used, skipping it
  forever. New rows now store NULL explicitly and migration 04 drops the
  default. Existing rows are deliberately untouched: a stored `0` is
  ambiguous ("revealed index 0" vs "never revealed") and rewriting it could
  cause address reuse.
- `update_last_revealed` was a plain `UPDATE`, letting a stale/replayed
  changeset move the derivation index backwards and silently reuse addresses;
  the update now never decreases the stored value.
- `Store::<Postgres>::read` ran at READ COMMITTED (per-statement snapshots),
  so a concurrent writer could produce a mixed-generation changeset; the read
  transaction now uses REPEATABLE READ.
- `initialize_network` had a check-then-set race that failed concurrent
  same-network builds spuriously with `SetNetworkFailure`; a lost race now
  re-validates instead.
- `Store` derived `Clone` with a `DB: Clone` bound that sqlx's `Postgres`/
  `Sqlite` marker types do not satisfy, making the impl unusable; a manual
  bound-free impl is provided.
- Reads anchored keychain rows on the `network` row, so descriptors and
  derivation state persisted by a changeset that carried no network were
  written but never read back (the tx/block invisibility defect, one table
  over); keychain rows are now read unconditionally.
- The sqlite backend had no network validation at all: its constructor took
  no network and any stored or incoming network was accepted. It now takes
  the network at construction (shared process-global with the postgres
  backend, so one process can never mix networks) and applies the same
  read/write guards. `Store::<Sqlite>::new` and `new_with_url` therefore
  take a `network` argument.
- `insert_descriptor`'s conflict update kept the stored `last_revealed`
  unconditionally, so replacing a descriptor under the same
  `(wallet_name, keychainkind)` made the new descriptor inherit the old
  derivation index and silently skip those addresses on load. The keep is
  now conditional on the descriptor being unchanged; a replaced descriptor
  restarts derivation at NULL.
- A `keychainkind` value outside `'External'`/`'Internal'` was silently
  ignored on load, dropping a keychain; corrupt rows now fail with
  `InvalidKeychainKind`.

## Security notes

- Without an explicit `sslmode`, postgres connections default to `prefer`, which
  silently falls back to plaintext if TLS negotiation fails. For any deployment where
  the database is not on the same host, require TLS in the connection URL
  (`?sslmode=require`, or `verify-full` to also authenticate the server).
- Connect with a least-privilege database role: the store only needs DML on the
  `bdk_wallet` schema (plus DDL when running migrations).
- Stored descriptors are sensitive (xpubs reveal the entire wallet history and
  structure); protect database backups and access accordingly.

## Testing

1. Install postgresql with `psql` tool. For example (macos):
   ```
   brew update
   brew install postgresql
   ```
2. Set DATABASE_TEST_URL to a postgres server the tests may use:
   ```
   export DATABASE_TEST_URL=postgresql://localhost/postgres
   ```
   The connected role must be allowed to `CREATE DATABASE`: every test creates
   (and later cleans up) its own uniquely named `bdk_sqlx_test_*` database, so
   tests never touch existing data and are safe to run in parallel. Do not
   point this at a production server.
3. Run tests:
   ```
   cargo test
   ```
   
## Example

1. Create empty test database:
   ```
   psql postgres
   postgres=# create database example_bdk_wallet;
   postgres=# \q
   ```
2. Set DATABASE_URL to test database:
   ```
   export DATABASE_URL=postgresql://localhost/example_bdk_wallet
   ```
3. Run example:
   ```
   cargo run --example bdk_sqlx_postgres
   ```