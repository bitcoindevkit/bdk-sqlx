-- Anchors belong to the monotone tx graph, not to the local chain. BDK allows
-- an anchor to be persisted before its transaction or block is known, and a
-- disconnected block must not erase anchor history. Drop both foreign keys (and
-- their ON DELETE CASCADE behavior) so anchor rows are independent, matching
-- bdk_chain's own SQLite persistence.
DROP TABLE IF EXISTS anchor_tx_new;
CREATE TABLE anchor_tx_new (
    wallet_name TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    anchor BLOB NOT NULL,
    txid TEXT NOT NULL,
    PRIMARY KEY (wallet_name, block_hash, txid)
);
INSERT INTO anchor_tx_new SELECT wallet_name, block_hash, anchor, txid FROM anchor_tx;
DROP TABLE anchor_tx;
ALTER TABLE anchor_tx_new RENAME TO anchor_tx;
CREATE INDEX IF NOT EXISTS idx_anchor_tx_txid ON anchor_tx (txid);
