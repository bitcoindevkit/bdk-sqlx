-- schema version control
CREATE TABLE IF NOT EXISTS version (
                                       version INTEGER
);
INSERT INTO version (version)
VALUES (1)
ON CONFLICT DO NOTHING;

-- network is the valid network for all other table data
CREATE TABLE IF NOT EXISTS network (
                                       wallet_name TEXT,
                                       name TEXT NOT NULL,
                                       UNIQUE (wallet_name, name)
);
CREATE INDEX idx_network_wallet_name ON network (wallet_name);

-- keychain is the json serialized keychain structure as JSONB,
-- descriptor is the complete descriptor string,
-- descriptor_id is a sha256::Hash id of the descriptor string w/o the checksum,
-- last revealed index is a u32
CREATE TABLE IF NOT EXISTS keychain (
                                        wallet_name TEXT,
                                        keychain JSONB NOT NULL,
                                        descriptor TEXT NOT NULL,
                                        descriptor_id BYTEA NOT NULL,
                                        last_revealed INTEGER DEFAULT 0,
                                        PRIMARY KEY (wallet_name, keychain)
);
CREATE INDEX idx_keychain_wallet_name ON keychain (wallet_name);

-- hash is block hash hex string,
-- block height is a u32,
CREATE TABLE IF NOT EXISTS block (
                                     wallet_name TEXT,
                                     hash TEXT NOT NULL,
                                     height INTEGER NOT NULL,
                                     PRIMARY KEY (wallet_name, hash)
);
CREATE INDEX idx_block_wallet_name ON block (wallet_name);

-- txid is transaction hash hex string (reversed)
-- whole_tx is a consensus encoded transaction,
-- last seen is a u64 unix epoch seconds
CREATE TABLE IF NOT EXISTS tx (
                                  wallet_name TEXT,
                                  txid TEXT NOT NULL,
                                  whole_tx BYTEA,
                                  last_seen BIGINT,
                                  PRIMARY KEY (wallet_name, txid)
);
CREATE INDEX idx_tx_wallet_name ON tx (wallet_name);

-- Outpoint txid hash hex string (reversed)
-- Outpoint vout
-- TxOut value as SATs
-- TxOut script consensus encoded
CREATE TABLE IF NOT EXISTS txout (
                                     wallet_name TEXT,
                                     txid TEXT NOT NULL,
                                     vout INTEGER NOT NULL,
                                     value BIGINT NOT NULL,
                                     script BYTEA NOT NULL,
                                     PRIMARY KEY (wallet_name, txid, vout)
);

CREATE INDEX idx_txout_wallet_name ON txout (wallet_name);

-- join table between anchor and tx
-- block hash hex string
-- anchor is a json serialized Anchor structure as JSONB,
-- txid is transaction hash hex string (reversed)
CREATE TABLE IF NOT EXISTS anchor_tx (
                                         wallet_name TEXT,
                                         block_hash TEXT NOT NULL,
                                         anchor JSONB NOT NULL,
                                         txid TEXT NOT NULL,
                                         UNIQUE (wallet_name, anchor, txid),
                                         FOREIGN KEY (wallet_name, block_hash) REFERENCES block(wallet_name, hash),
                                         FOREIGN KEY (wallet_name, txid) REFERENCES tx(wallet_name, txid)
);
CREATE INDEX idx_anchor_tx_wallet_name ON anchor_tx (wallet_name);