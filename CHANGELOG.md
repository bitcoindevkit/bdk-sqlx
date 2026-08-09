# Changelog

All notable defects found in review and fixed are listed here. Each fix is
guarded by an always-on regression test in the suite (`src/test.rs` and
`tests/builder_network.rs`).

## Unreleased

### Fixed

- Two writers persisting different block hashes for the same previously
  unoccupied height raced the block table's two unique indexes on postgres:
  the loser's `DELETE` could not see the winner's uncommitted row, and its
  `INSERT` then violated `idx_block_wallet_height` — an index the upsert's
  `(wallet_name, hash)` conflict target does not cover — aborting the loser's
  whole changeset with a raw `23505`. Block writes are now serialized per
  wallet with a transaction-scoped advisory lock; the loser waits for the
  winner to commit, then sees and replaces its row (last-writer-wins), exactly
  as if the writes had been issued sequentially. sqlite needs no equivalent:
  its single-writer lock already serializes the same interleaving. Reproduced
  before the fix (`duplicate key value violates unique constraint
  "idx_block_wallet_height"`); regression test
  `concurrent_block_writes_at_same_height_both_land` covers both backends.
- The `tx.last_seen` upsert overwrote unconditionally, so a stale or replayed
  changeset moved the timestamp backwards, contradicting bdk_chain's own
  `Merge` (last_seen only ever increases). The conflict update now keeps the
  maximum on both backends, matching the monotonic `last_revealed` update.
  Regression test `last_seen_never_regresses` covers both backends.
- The sqlite backend propagated raw `BdkSqlxError::Sqlx` for statement
  failures while postgres wrapped them in `BdkSqlxError::QueryError` with
  table context, so callers could not match on one error kind for "the write
  failed at the database". sqlite now wraps with the same table labels.

### Added

- `SqliteStoreBuilder`, mirroring `PgStoreBuilder`
  (`new(wallet_name).network(..).migrate(..).pool(..).build()` /
  `build_with_url(..)`; `build_with_url(None)` builds the single-connection
  in-memory store). `Store::<Sqlite>::new_with_url` now delegates to it.
- `Store::<Sqlite>::migrate()`, mirroring `Store::<Postgres>::migrate`.

### Changed

- Tests no longer panic when `DATABASE_TEST_URL` is unset: postgres-backend
  tests skip gracefully (with a one-time notice) and the sqlite backend still
  runs. CI sets the variable, so full coverage always runs there.
- `#[tracing::instrument]` on persist-path helpers is uniformly `skip_all` on
  both backends: one rule, no span records arguments.
- Module-internal free functions were `pub` in private modules (unreachable,
  misleading); they are now `pub(crate)`.
- The README's "Resolved defects" section moved here.

## Resolved defects (previous review round)

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
