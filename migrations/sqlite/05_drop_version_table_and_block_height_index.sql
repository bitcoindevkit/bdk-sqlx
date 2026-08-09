-- Schema hygiene. The version table is dead schema from before sqlx's
-- migration bookkeeping, and idx_block_height(height) was made redundant by
-- migration 03's unique (wallet_name, height) index, which serves the same
-- lookups.
DROP TABLE IF EXISTS version;
DROP INDEX IF EXISTS idx_block_height;
