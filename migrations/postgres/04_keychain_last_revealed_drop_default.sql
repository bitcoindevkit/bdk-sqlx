-- The keychain table declared `last_revealed INTEGER DEFAULT 0`, which made a
-- wallet persisted before its first address reveal reload as if index 0 had
-- been revealed, skipping it forever. The store now inserts NULL explicitly,
-- so the default is removed. Existing values are left untouched on purpose:
-- a stored 0 is ambiguous ("revealed index 0" vs "never revealed") and cannot
-- be rewritten without risking address reuse.
ALTER TABLE "bdk_wallet"."keychain" ALTER COLUMN last_revealed DROP DEFAULT;
