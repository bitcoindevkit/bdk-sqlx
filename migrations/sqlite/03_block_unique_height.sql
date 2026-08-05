-- A wallet's chain has exactly one block hash per height, but the block table only
-- enforced uniqueness on (wallet_name, hash): a reorg that replaced the block at a
-- height left both rows behind and made loads nondeterministic. Remove duplicates,
-- keeping the most recently inserted row (their anchors cascade away), and enforce
-- one row per height from here on.
DELETE FROM block WHERE rowid NOT IN (
    SELECT MAX(rowid) FROM block GROUP BY wallet_name, height
);
CREATE UNIQUE INDEX idx_block_wallet_height ON block (wallet_name, height);
