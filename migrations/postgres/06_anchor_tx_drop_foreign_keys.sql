-- Anchors belong to the monotone tx graph, not to the local chain. BDK allows
-- an anchor to be persisted before its transaction or block is known, and a
-- disconnected block must not erase anchor history. Drop every foreign key on
-- anchor_tx (including legacy constraints with non-default names) so anchor
-- rows are independent, matching bdk_chain's own SQLite persistence.
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
          AND c.contype = 'f'
    LOOP
        EXECUTE format(
            'ALTER TABLE "bdk_wallet"."anchor_tx" DROP CONSTRAINT %I',
            con.conname
        );
    END LOOP;
END $$;
