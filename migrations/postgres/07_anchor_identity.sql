-- bdk_core anchors are ordered and compared over the full
-- (block height, block hash, confirmation time) identity. The old
-- (wallet_name, block_hash, txid) key collapsed distinct anchors that shared a
-- block and transaction, and an unconditional payload update let a stale
-- changeset regress confirmation_time. Store the full identity in the key so
-- every distinct anchor keeps its own row and no anchor can overwrite another.
ALTER TABLE "bdk_wallet"."anchor_tx" ADD COLUMN block_height INTEGER;
ALTER TABLE "bdk_wallet"."anchor_tx" ADD COLUMN confirmation_time BIGINT;
UPDATE "bdk_wallet"."anchor_tx"
SET block_height = (anchor -> 'block_id' ->> 'height')::integer,
    confirmation_time = (anchor ->> 'confirmation_time')::bigint;
ALTER TABLE "bdk_wallet"."anchor_tx" ALTER COLUMN block_height SET NOT NULL;
ALTER TABLE "bdk_wallet"."anchor_tx" ALTER COLUMN confirmation_time SET NOT NULL;

DO $$
DECLARE
    con record;
BEGIN
    FOR con IN
        SELECT c.conname
        FROM pg_constraint c
        JOIN pg_class t ON t.oid = c.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = 'bdk_wallet'
          AND t.relname = 'anchor_tx'
          AND c.contype = 'p'
    LOOP
        EXECUTE format(
            'ALTER TABLE "bdk_wallet"."anchor_tx" DROP CONSTRAINT %I',
            con.conname
        );
    END LOOP;
END $$;

ALTER TABLE "bdk_wallet"."anchor_tx"
    ADD PRIMARY KEY (wallet_name, txid, block_height, block_hash, confirmation_time);
