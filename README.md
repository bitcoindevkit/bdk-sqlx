# bdk-sqlx

## Status

This crate is still **EXPERIMENTAL** do not use with mainnet wallets.

## Testing

1. Install postgresql with `psql` tool. For example (macos):
   ```
   brew update
   brew install postgresql
   ```
2. Create empty test database:
   ```
   psql postgres
   postgres=# create database test_bdk_wallet;
   ```
3. Set DATABASE_URL to test database:
   ```
   export DATABASE_TEST_URL=postgresql://localhost/test_bdk_wallet
   ```
4. Run tests, must use a single test thread since we reuse the postgres db:
   ```
   cargo test -- --test-threads=1
   ```
5. Run example:
   ```
   cargo run --example bdk_sqlx_postgres
   ```