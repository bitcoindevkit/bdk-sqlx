-- A wallet's chain has exactly one block hash per height, but the block table only
-- enforced uniqueness on (wallet_name, hash): a reorg that replaced the block at a
-- height left both rows behind and made loads nondeterministic. Remove duplicates
-- (survivor arbitrary among the duplicates; their anchors cascade away) and enforce
-- one row per height from here on.
DELETE FROM "bdk_wallet"."block" b
WHERE EXISTS (
    SELECT 1 FROM "bdk_wallet"."block" b2
    WHERE b2.wallet_name = b.wallet_name AND b2.height = b.height AND b2.ctid > b.ctid
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_block_wallet_height ON "bdk_wallet"."block" (wallet_name, height);
