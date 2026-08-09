-- The keychain table declared `last_revealed INTEGER DEFAULT 0`, which made a
-- wallet persisted before its first address reveal reload as if index 0 had
-- been revealed, skipping it forever. The store now inserts NULL explicitly.
-- SQLite cannot alter a column default in place, so the table is rebuilt (data
-- preserved; a stored 0 is ambiguous and deliberately left as-is).
CREATE TABLE keychain_new (
    wallet_name TEXT NOT NULL,
    keychainkind TEXT NOT NULL,
    descriptor TEXT NOT NULL,
    descriptor_id BLOB NOT NULL,
    last_revealed INTEGER,
    PRIMARY KEY (wallet_name, keychainkind)
);
INSERT INTO keychain_new
    SELECT wallet_name, keychainkind, descriptor, descriptor_id, last_revealed FROM keychain;
DROP TABLE keychain;
ALTER TABLE keychain_new RENAME TO keychain;
