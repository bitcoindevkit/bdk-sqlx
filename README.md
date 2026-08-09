# bdk-sqlx

## Status

This crate is still **EXPERIMENTAL** do not use with mainnet wallets.

Defects found in review and fixed (each guarded by an always-on regression
test) are listed in [CHANGELOG.md](CHANGELOG.md).

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

   Without `DATABASE_TEST_URL` the postgres-backend tests skip gracefully and
   only the sqlite backend runs; set it for full coverage (CI always does).
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