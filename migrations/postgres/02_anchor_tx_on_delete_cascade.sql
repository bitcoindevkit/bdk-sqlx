-- Databases created before the anchor_tx foreign keys included ON DELETE CASCADE
-- reject reorg-driven block deletion while anchor_tx rows still reference the
-- block, wedging all further persistence. Recreate such constraints in place.
-- No-op for databases created from the current 01 migration.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'bdk_wallet' AND t.relname = 'anchor_tx'
          AND c.contype = 'f' AND c.confdeltype <> 'c'
    ) THEN
        ALTER TABLE "bdk_wallet"."anchor_tx"
            DROP CONSTRAINT IF EXISTS anchor_tx_wallet_name_block_hash_fkey,
            DROP CONSTRAINT IF EXISTS anchor_tx_wallet_name_txid_fkey;
        ALTER TABLE "bdk_wallet"."anchor_tx"
            ADD CONSTRAINT anchor_tx_wallet_name_block_hash_fkey
                FOREIGN KEY (wallet_name, block_hash)
                REFERENCES "bdk_wallet"."block"(wallet_name, hash) ON DELETE CASCADE,
            ADD CONSTRAINT anchor_tx_wallet_name_txid_fkey
                FOREIGN KEY (wallet_name, txid)
                REFERENCES "bdk_wallet"."tx"(wallet_name, txid) ON DELETE CASCADE;
    END IF;
END $$;
