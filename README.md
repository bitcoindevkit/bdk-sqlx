# bdk-sqlx

## Status

This crate is still **EXPERIMENTAL** do not use with mainnet wallets.

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