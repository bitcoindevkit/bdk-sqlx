-- Rebuild anchor_tx so its foreign keys cascade on block/tx deletion.
-- Without this, a reorg (which deletes the disconnected block row) is rejected
-- with a FK violation while anchor_tx rows still reference the block, wedging
-- all further persistence. SQLite cannot alter FK clauses in place, so the
-- table is rebuilt.
CREATE TABLE anchor_tx_new (
    wallet_name TEXT NOT NULL,
    block_hash TEXT NOT NULL,
    anchor BLOB NOT NULL,
    txid TEXT NOT NULL,
    PRIMARY KEY (wallet_name, block_hash, txid),
    FOREIGN KEY (wallet_name, block_hash) REFERENCES block(wallet_name, hash) ON DELETE CASCADE,
    FOREIGN KEY (wallet_name, txid) REFERENCES tx(wallet_name, txid) ON DELETE CASCADE
);
INSERT INTO anchor_tx_new SELECT wallet_name, block_hash, anchor, txid FROM anchor_tx;
DROP TABLE anchor_tx;
ALTER TABLE anchor_tx_new RENAME TO anchor_tx;
CREATE INDEX idx_anchor_tx_txid ON anchor_tx (txid);
