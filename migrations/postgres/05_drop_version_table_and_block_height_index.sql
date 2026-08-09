-- Schema hygiene. The version table is dead schema from the hand-rolled
-- versioning scheme that sqlx's migration bookkeeping replaced; migration 01
-- created it only so databases from before the migrator could be adopted
-- unchanged. idx_block_height(height) was made redundant by migration 03's
-- unique (wallet_name, height) index, which serves the same lookups.
DROP TABLE IF EXISTS "bdk_wallet"."version";
DROP INDEX IF EXISTS "bdk_wallet"."idx_block_height";
