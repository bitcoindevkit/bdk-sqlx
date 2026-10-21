-- bdk_core anchors are ordered and compared over the full
-- (block height, block hash, confirmation time) identity. The old
-- (wallet_name, block_hash, txid) key collapsed distinct anchors that shared a
-- block and transaction, and an unconditional payload update let a stale
-- changeset regress confirmation_time. Store the full identity in the key so
-- every distinct anchor keeps its own row and no anchor can overwrite another.
DROP TABLE IF EXISTS anchor_tx_new;
CREATE TABLE anchor_tx_new (
    wallet_name TEXT NOT NULL,
    txid TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    confirmation_time INTEGER NOT NULL,
    anchor BLOB NOT NULL,
    PRIMARY KEY (wallet_name, txid, block_height, block_hash, confirmation_time)
);
INSERT INTO anchor_tx_new
    (wallet_name, txid, block_height, block_hash, confirmation_time, anchor)
SELECT
    wallet_name,
    txid,
    json_extract(json(anchor), '$.block_id.height'),
    block_hash,
    json_extract(json(anchor), '$.confirmation_time'),
    anchor
FROM anchor_tx;
DROP TABLE anchor_tx;
ALTER TABLE anchor_tx_new RENAME TO anchor_tx;
CREATE INDEX IF NOT EXISTS idx_anchor_tx_txid ON anchor_tx (txid);
